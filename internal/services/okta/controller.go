package okta

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/getsentry/raven-go"

	cfg "github.com/kiwicom/iam/configs"
	"github.com/kiwicom/iam/internal/monitoring"
	"github.com/kiwicom/iam/internal/storage"
)

// BoocsekAttributes contains formatted Boocsek attributes provided by Okta.
type BoocsekAttributes struct {
	Site        string   `json:"site"`
	Position    string   `json:"position"`
	Channel     string   `json:"channel"`
	Tier        string   `json:"tier"`
	Team        string   `json:"team"`
	TeamManager string   `json:"teamManager"`
	Staff       string   `json:"staff"`
	State       string   `json:"state"`
	KiwibaseID  int32    `json:"kiwibaseId"`
	Substate    string   `json:"substate"`
	Skills      []string `json:"skills"`
}

// User contains formatted user data provided by Okta.
type User struct {
	OktaID                string            `json:"oktaId,omitempty"` // Exported to be cache-able
	EmployeeNumber        string            `json:"employeeNumber"`
	FirstName             string            `json:"firstName"`
	LastName              string            `json:"lastName"`
	Position              string            `json:"position"`
	Department            string            `json:"department"`
	Email                 string            `json:"email"`
	Location              string            `json:"location"`
	IsVendor              bool              `json:"isVendor"`
	TeamMembership        []string          `json:"teamMembership"` // Deprecated
	OrganizationStructure string            `json:"orgStructure"`
	GroupMembership       []Group           `json:"groupMembership,omitempty"`
	Manager               string            `json:"manager"`
	Permissions           []string          `json:"permissions"`
	BoocsekAttributes     BoocsekAttributes `json:"boocsek"`
}

const groupMembershipPrefix = "group-membership:"

// GetUser returns an Okta user by email. It first tries to get it from cache,
// and if not present there, it will fetch it from Okta API.
func (c *Client) GetUser(email string) (User, error) {
	var user User
	err := c.cache.Get(email, &user)
	if err == nil {
		// User email is not specified only in case the user was not found.
		if user.Email == "" {
			return User{}, ErrUserNotFound
		}
		// Cache hit
		return user, nil
	}

	if err != storage.ErrNotFound {
		// Not a cache hit, not a cache miss, something went wrong
		return User{}, err
	}

	// Cache miss
	// Deduplicate network calls and cache writes if this controller is called
	// multiple times concurrently.
	val, err, _ := c.group.Do(email, func() (interface{}, error) {
		lockErr := c.lock.Create(email, 5*time.Second)
		if lockErr == storage.ErrLockExists {
			// If there was a lock for this user, it means another instance was
			// fetching its data recently, in that case we should be able to just get
			// the data from cache.
			return c.GetUser(email)
		}
		defer c.lock.Delete(email)

		user, fetchErr := c.fetchUser(email)
		if fetchErr != nil {
			if fetchErr == ErrUserNotFound {
				cacheErr := c.cache.Set(email, User{}, cfg.Expirations.User)
				raven.CaptureError(cacheErr, nil)
			}

			return User{}, fetchErr
		}

		cacheErr := c.cache.Set(user.Email, user, cfg.Expirations.User)
		if cacheErr != nil {
			raven.CaptureError(cacheErr, nil)
		}

		return user, nil
	})

	if err != nil {
		return User{}, err
	}

	return val.(User), nil
}

// AddPermissions adds Okta groups to the given user object.
func (c *Client) AddPermissions(user *User, service string) error {
	cachedGroupMemberships := make(map[string]map[string]bool)
	user.Permissions = make([]string, 0)

	err := c.cache.Get(groupMembershipPrefix+service, &cachedGroupMemberships)
	if err != nil {
		if err != storage.ErrNotFound {
			return err
		}

		timestamp := time.Time{}
		_ = c.cache.Get("groups-sync-timestamp", &timestamp)
		if time.Now().Before(timestamp.Add(10 * time.Minute)) {
			// If there are no groups cached for the service and it's less than 10
			// minutes from the last sync, we assume that there are no groups for that
			// service.

			return nil
		}

		// Get cached groups or ask Okta in case of cache miss.
		groups, err := c.getUserGroups(user)
		if err != nil {
			return err
		}

		groupPrefix := iamGroupPrefix + strings.ToLower(service) + "."

		for _, group := range groups {
			if strings.HasPrefix(group.Name, groupPrefix) {
				user.Permissions = append(user.Permissions, strings.Replace(group.Name, groupPrefix, "", 1))
			}
		}

		return nil
	}

	for groupName, users := range cachedGroupMemberships {
		if users[user.Email] {
			user.Permissions = append(user.Permissions, groupName)
		}
	}

	return nil
}

// GetGroups retrieves Okta groups.
func (c *Client) GetGroups() ([]Group, error) {
	var groups []Group
	err := c.cache.Get("groups", &groups)

	return groups, err
}

// SyncUsers gets all users from Okta and saves them into cache.
func (c *Client) SyncUsers() {
	lockErr := c.lock.Create("sync_users", 5*time.Minute)
	if lockErr == storage.ErrLockExists {
		log.Println("Aborted, users were already fetched")

		return
	}
	defer c.lock.Delete("sync_users")

	users, err := c.fetchAllUsers()
	if err != nil {
		log.Println("Error fetching users", err)
		c.metrics.Incr("okta_sync", monitoring.Tag("type", "users"), monitoring.Tag("status", "error"))
		raven.CaptureError(err, nil)

		return
	}

	pairs := make(map[string]interface{}, len(users))
	for i := range users {
		user := &users[i]
		pairs[user.Email] = user
	}

	err = c.cache.MSet(pairs, time.Hour*24)
	if err != nil {
		log.Println("Error caching users", err)
		c.metrics.Incr("okta_sync", monitoring.Tag("type", "users"), monitoring.Tag("status", "error"))
		raven.CaptureError(err, nil)

		return
	}
	log.Println("Cached", len(users), "users")

	c.metrics.Incr("okta_sync", monitoring.Tag("type", "users"), monitoring.Tag("status", "ok"))
}

// SyncGroups gets all groups from Okta and saves them into cache.
func (c *Client) SyncGroups() {
	lockErr := c.lock.Create("sync_groups", 10*time.Minute)
	if lockErr == storage.ErrLockExists {
		log.Println("Aborted, groups were already fetched")

		return
	}
	defer c.lock.Delete("sync_groups")
	syncStart := time.Now().UTC()

	groups, err := c.fetchGroups("", c.getLastSyncTime())
	if err != nil {
		log.Println("Error fetching groups", err)
		c.metrics.Incr("okta_sync", monitoring.Tag("type", "groups"), monitoring.Tag("status", "error"))
		raven.CaptureError(err, nil)

		return
	}

	// We need to keep track of users assigned to various groups.
	groupMemberships, err := c.fetchGroupMemberships(groups)
	if err != nil {
		log.Println("Error fetching group memberships ", err)
		c.metrics.Incr("okta_sync", monitoring.Tag("type", "groups"), monitoring.Tag("status", "error"))
		raven.CaptureError(err, nil)

		return
	}

	if len(groupMemberships) > 0 {
		if err = c.updateGroupMemberships(groupMemberships); err != nil {
			log.Println("Error updating group memeberships ", err)
			c.metrics.Incr("okta_sync", monitoring.Tag("type", "groups"), monitoring.Tag("status", "error"))
			raven.CaptureError(err, nil)

			return
		}
	}

	if err = c.cache.Set("groups-sync-timestamp", syncStart, cfg.Expirations.GroupsLastSync); err != nil {
		log.Println("Error while caching last synchronization time ", err)
		c.metrics.Incr("okta_sync", monitoring.Tag("type", "groups"), monitoring.Tag("status", "error"))
		raven.CaptureError(err, nil)

		return
	}
	log.Println("Cached", len(groupMemberships), "group memberships")
	c.metrics.Incr("okta_sync", monitoring.Tag("type", "groups"), monitoring.Tag("status", "ok"))
}

func (c *Client) getLastSyncTime() string {
	timestamp := time.Time{}
	if err := c.cache.Get("groups-sync-timestamp", &timestamp); err != nil {
		if err != storage.ErrNotFound {
			log.Println("[ERROR]", err.Error())
			raven.CaptureError(err, nil)
		}
	}

	return oktaTimeFormat(timestamp)
}

func oktaTimeFormat(t time.Time) string {
	return fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.0Z",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second())
}
