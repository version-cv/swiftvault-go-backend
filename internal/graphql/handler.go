package graphql

import (
    "net/http"
    "backend/internal/auth"
    "context"
    "encoding/json"
    "github.com/graphql-go/graphql"
    "backend/internal/handlers"
)

type authContextKey struct{}

func GraphQLHandler(schema *graphql.Schema) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        

        claims, err := handlers.GetClaimsFromContext(r.Context())
        if err != nil {
            http.Error(w, "Authentication context missing after middleware", http.StatusUnauthorized)
            return
        }

        // Parse GraphQL request
        var params struct {
            Query           string                 `json:"query"`
            OperationName string                 `json:"operationName"`
            Variables     map[string]interface{} `json:"variables"`
        }

        if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
            http.Error(w, "Invalid JSON", http.StatusBadRequest)
            return
        }

        result := graphql.Do(graphql.Params{
            Schema:          *schema,
            RequestString:   params.Query,
            OperationName:   params.OperationName,
            VariableValues:  params.Variables,
            // Use the UserID from the claims already validated by the middleware
            Context:         context.WithValue(r.Context(), authContextKey{}, claims.UserID),
        })

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
    })
}