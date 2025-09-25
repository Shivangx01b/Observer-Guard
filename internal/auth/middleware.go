package auth

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

// AuthConfig represents authentication configuration
type AuthConfig struct {
	JWTManager *JWTManager
	APIKey     string
	Enabled    bool
	SkipPaths  []string
}

// RequireAuth creates an authentication middleware
func RequireAuth(config AuthConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !config.Enabled {
			return c.Next()
		}

		// Check if path should be skipped
		path := c.Path()
		for _, skipPath := range config.SkipPaths {
			if strings.HasPrefix(path, skipPath) {
				return c.Next()
			}
		}

		// Skip authentication for health checks and metrics
		if path == "/health" || path == "/metrics" || path == "/api/v1/version" {
			return c.Next()
		}

		// Try API Key authentication first
		if apiKey := c.Get("X-API-Key"); apiKey != "" {
			if config.APIKey != "" && apiKey == config.APIKey {
				c.Locals("auth_method", "api_key")
				return c.Next()
			}
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   true,
				"message": "Invalid API key",
			})
		}

		// Try JWT authentication
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   true,
				"message": "Authorization header required",
			})
		}

		// Extract token from Bearer header
		tokenString := extractBearerToken(authHeader)
		if tokenString == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   true,
				"message": "Invalid authorization header format",
			})
		}

		// Validate JWT token
		claims, err := config.JWTManager.ValidateToken(tokenString)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   true,
				"message": "Invalid or expired token",
			})
		}

		// Set user information in context
		c.Locals("user_id", claims.UserID)
		c.Locals("username", claims.Username)
		c.Locals("roles", claims.Roles)
		c.Locals("auth_method", "jwt")

		return c.Next()
	}
}

// RequireRole creates a role-based authorization middleware
func RequireRole(requiredRoles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userRoles, ok := c.Locals("roles").([]string)
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   true,
				"message": "No roles found in token",
			})
		}

		// Check if user has any of the required roles
		hasRole := false
		for _, required := range requiredRoles {
			for _, userRole := range userRoles {
				if userRole == required {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}

		if !hasRole {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   true,
				"message": "Insufficient permissions",
			})
		}

		return c.Next()
	}
}

// RequirePermission creates a permission-based authorization middleware
func RequirePermission(permission string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userRoles, ok := c.Locals("roles").([]string)
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   true,
				"message": "No roles found in token",
			})
		}

		// Check if user has permission based on roles
		hasPermission := checkPermission(userRoles, permission)
		if !hasPermission {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   true,
				"message": "Permission denied",
			})
		}

		return c.Next()
	}
}

// RateLimitByUser creates a user-specific rate limiting middleware
func RateLimitByUser() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Implementation would use user ID for rate limiting
		// For now, just pass through
		return c.Next()
	}
}

// AuditLog creates an audit logging middleware
func AuditLog() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Log the request details for auditing
		userID := c.Locals("user_id")
		username := c.Locals("username")
		method := c.Method()
		path := c.Path()
		ip := c.IP()

		// Process the request
		err := c.Next()

		// Log after processing (including response status)
		status := c.Response().StatusCode()

		// In a real implementation, this would go to a proper audit log
		if userID != nil {
			// Log authenticated requests
			_ = userID
			_ = username
			_ = method
			_ = path
			_ = ip
			_ = status
			// log.Printf("AUDIT: user=%s method=%s path=%s ip=%s status=%d", username, method, path, ip, status)
		}

		return err
	}
}

// Security headers middleware
func SecurityHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Set security headers
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("X-XSS-Protection", "1; mode=block")
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Set("Content-Security-Policy", "default-src 'self'")

		return c.Next()
	}
}

// extractBearerToken extracts the token from Authorization header
func extractBearerToken(authHeader string) string {
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return parts[1]
}

// checkPermission checks if user roles have the required permission
func checkPermission(userRoles []string, permission string) bool {
	// Define role permissions (in a real app, this would be in a database)
	rolePermissions := map[string][]string{
		"admin": {
			"read:events", "write:events", "delete:events",
			"read:threats", "write:threats", "delete:threats",
			"read:policies", "write:policies", "delete:policies",
			"read:system", "write:system",
			"manage:users",
		},
		"analyst": {
			"read:events", "read:threats", "write:threats",
			"read:policies", "write:policies",
			"read:system",
		},
		"viewer": {
			"read:events", "read:threats", "read:policies", "read:system",
		},
	}

	for _, role := range userRoles {
		if permissions, exists := rolePermissions[role]; exists {
			for _, perm := range permissions {
				if perm == permission {
					return true
				}
			}
		}
	}
	return false
}