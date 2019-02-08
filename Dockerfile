FROM golang:latest 
RUN mkdir /app 
ADD . /app/ 
WORKDIR /app 
RUN go get -d ./... && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o build ./main
CMD ["/app/build"]
