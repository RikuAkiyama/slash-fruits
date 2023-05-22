# Use the official Go image to create a build artifact.
FROM golang:1.20 as builder

# Copy local code to the container image.
WORKDIR /app
COPY . .

# Download dependencies.
RUN go mod download

# Build the binary.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o server

# Use the official lightweight Alpine image for a lean production container.
FROM alpine:3.14
RUN apk --no-cache add ca-certificates

# Copy the binary to the production image from the builder stage.
COPY --from=builder /app/server /server

# Indicate the application listens on port 8080.
EXPOSE 8080

# Run the web service on container startup.
CMD ["/server"]
