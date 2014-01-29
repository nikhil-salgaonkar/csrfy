package csrfy

import (
        "bytes"
        "crypto/hmac"
        "crypto/sha1"
        "encoding/base64"
        "fmt"
        "strconv"
        "strings"
        "time"
)

// The duration that CSRF tokens are valid.
const timeout = 30 * time.Minute

// clean sanitizes a string for inclusion in a token by replacing all ":"s.
func clean(s string) string {
        return strings.Replace(s, ":", "_", -1)
}

// convinience wrapper for generateAtTime() at time.Now()
func Generate(key, userID string) string {
        return generateAtTime(key, userID, time.Now())
}

// generateAtTime is like Generate, but returns a token that expires 30 minutes from now.
func generateAtTime(key, userID string, now time.Time) string {
        h := hmac.New(sha1.New, []byte(key))
        fmt.Fprintf(h, "%s:%d", clean(userID), now.UnixNano())
        tok := fmt.Sprintf("%s:%d", h.Sum(nil), now.UnixNano())
        return base64.URLEncoding.EncodeToString([]byte(tok))
}

// convinience wrapper for validAtTime() at time.Now()
func Valid(token, key, userID string) bool {
        return validAtTime(token, key, userID, time.Now())
}

// Valid returns true if token is a valid, unexpired token returned by Generate.
func validAtTime(token, key, userID string, now time.Time) bool {
        // Decode the token.
        data, err := base64.URLEncoding.DecodeString(token)
        if err != nil {
                return false
        }

        // Extract the issue time of the token.
        sep := bytes.LastIndex(data, []byte{':'})
        if sep < 0 {
                return false
        }
        nanos, err := strconv.ParseInt(string(data[sep+1:]), 10, 64)
        if err != nil {
                return false
        }
        issueTime := time.Unix(0, nanos)

        // Check that the token is not expired.
        if now.Sub(issueTime) >= timeout {
                return false
        }

        // Check that the token is not from the future.
        // Allow 1 minute grace period in case the token is being verified on a
        // machine whose clock is behind the machine that issued the token.
        if issueTime.After(now.Add(1 * time.Minute)) {
                return false
        }

        // Check that the token matches the expected value.
        expected := generateAtTime(key, userID, issueTime)
        return token == expected
}