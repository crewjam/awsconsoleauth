FROM golang

# Pull in depenedencies we know we'll need so we don't have to re-pull them
# every time the source changes
RUN \
  go get golang.org/x/oauth2 && \
  go get github.com/dgrijalva/jwt-go && \
  go get github.com/crowdmob/goamz/... && \
  true

ADD . /go/src/github.com/crewjam/awsconsoleauth
WORKDIR /go/src/github.com/crewjam/awsconsoleauth

# Pull in any missing dependencies
RUN go get ./...

CMD go run http.go \
  -google-client-id=$GOOGLE_CLIENT_ID \
  -google-client-secret=$GOOGLE_CLIENT_SECRET \
  -google-domain=$GOOGLE_DOMAIN \
  -listen=0.0.0.0:80
