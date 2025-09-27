package graphql

import (
    "net/http"
    "backend/internal/auth"
	"context"
	"encoding/json"
    "github.com/graphql-go/graphql"
)

func GraphQLHandler(schema *graphql.Schema) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from header
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		// Validate token
		claims, err := auth.ValidateToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Parse GraphQL request
		var params struct {
			Query         string                 `json:"query"`
			OperationName string                 `json:"operationName"`
			Variables     map[string]interface{} `json:"variables"`
		}

		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Execute GraphQL query with user context
		result := graphql.Do(graphql.Params{
			Schema:         *schema,
			RequestString:  params.Query,
			OperationName:  params.OperationName,
			VariableValues: params.Variables,
			Context:        context.WithValue(r.Context(), authContextKey{}, claims.UserID),
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
}