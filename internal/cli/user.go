package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"text/tabwriter"

	"ztap/internal/auth"
	"ztap/internal/config"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newUserCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "user",
		Short: "Manage users and authentication",
		Long:  `Create, list, and manage users for ZTAP authentication`,
	}
	c.AddCommand(newCreateUserCmd(app))
	c.AddCommand(newListUsersCmd(app))
	c.AddCommand(newChangePasswordCmd(app))
	c.AddCommand(newDisableUserCmd(app))
	c.AddCommand(newEnableUserCmd(app))
	c.AddCommand(newLoginCmd(app))
	c.AddCommand(newLogoutCmd(app))
	return c
}

func newCreateUserCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "create <username>",
		Short: "Create a new user",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			username := args[0]
			role, _ := cmd.Flags().GetString("role")

			central, err := app.Config()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			// Get auth manager
			am, err := getAuthManager(central)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			defer func() { _ = am.Close() }()

			// Prompt for password
			fmt.Print("Enter password: ")
			passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				fmt.Printf("Error reading password: %v\n", err)
				os.Exit(1)
			}

			fmt.Print("Confirm password: ")
			confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				fmt.Printf("Error reading password: %v\n", err)
				os.Exit(1)
			}

			password := string(passwordBytes)
			confirm := string(confirmBytes)

			if password != confirm {
				fmt.Println("Error: Passwords do not match")
				os.Exit(1)
			}

			if len(password) < 8 {
				fmt.Println("Error: Password must be at least 8 characters")
				os.Exit(1)
			}

			// Create user
			if err := am.CreateUser(username, password, auth.Role(role)); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("User '%s' created successfully with role '%s'\n", username, role)
		},
	}
	c.Flags().StringP("role", "r", "operator", "User role (admin, operator, viewer)")
	return c
}

func newListUsersCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "list",
		Short: "List all users",
		Run: func(cmd *cobra.Command, args []string) {
			central, err := app.Config()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			am, err := getAuthManager(central)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			defer func() { _ = am.Close() }()

			users := am.ListUsers()
			if len(users) == 0 {
				fmt.Println("No users found")
				return
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "USERNAME\tROLE\tENABLED\tCREATED\tLAST LOGIN")
			_, _ = fmt.Fprintln(w, "--------\t----\t-------\t-------\t----------")

			for _, user := range users {
				lastLogin := "Never"
				if !user.LastLogin.IsZero() {
					lastLogin = user.LastLogin.Format("2006-01-02 15:04")
				}

				enabled := "Yes"
				if !user.Enabled {
					enabled = "No"
				}

				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					user.Username,
					user.Role,
					enabled,
					user.CreatedAt.Format("2006-01-02"),
					lastLogin,
				)
			}
			_ = w.Flush()
		},
	}
	return c
}

func newChangePasswordCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "change-password <username>",
		Short: "Change user password",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			username := args[0]

			central, err := app.Config()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			am, err := getAuthManager(central)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			defer func() { _ = am.Close() }()

			// Prompt for old password
			fmt.Print("Enter current password: ")
			oldPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				fmt.Printf("Error reading password: %v\n", err)
				os.Exit(1)
			}

			// Prompt for new password
			fmt.Print("Enter new password: ")
			newPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				fmt.Printf("Error reading password: %v\n", err)
				os.Exit(1)
			}

			fmt.Print("Confirm new password: ")
			confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				fmt.Printf("Error reading password: %v\n", err)
				os.Exit(1)
			}

			newPassword := string(newPasswordBytes)
			confirm := string(confirmBytes)

			if newPassword != confirm {
				fmt.Println("Error: Passwords do not match")
				os.Exit(1)
			}

			if len(newPassword) < 8 {
				fmt.Println("Error: Password must be at least 8 characters")
				os.Exit(1)
			}

			// Change password
			if err := am.ChangePassword(username, string(oldPasswordBytes), newPassword); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Password changed successfully for user '%s'\n", username)
		},
	}
	return c
}

func newDisableUserCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "disable <username>",
		Short: "Disable a user account",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			username := args[0]

			central, err := app.Config()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			am, err := getAuthManager(central)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			defer func() { _ = am.Close() }()

			if err := am.DisableUser(username); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("User '%s' disabled\n", username)
		},
	}
	return c
}

func newEnableUserCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "enable <username>",
		Short: "Enable a user account",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			username := args[0]

			central, err := app.Config()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			am, err := getAuthManager(central)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			defer func() { _ = am.Close() }()

			if err := am.EnableUser(username); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("User '%s' enabled\n", username)
		},
	}
	return c
}

func newLoginCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "login",
		Short: "Authenticate and create a session",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print("Username: ")
			var username string
			_, _ = fmt.Scanln(&username)

			fmt.Print("Password: ")
			passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				fmt.Printf("Error reading password: %v\n", err)
				os.Exit(1)
			}

			central, err := app.Config()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			am, err := getAuthManager(central)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			defer func() { _ = am.Close() }()

			session, err := am.Authenticate(context.Background(), username, string(passwordBytes))
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			// Save token to file
			tokenFile := getTokenFile()
			if err := os.WriteFile(tokenFile, []byte(session.Token), 0600); err != nil {
				fmt.Printf("Error saving token: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("Login successful")
			fmt.Printf("Session expires: %s\n", session.ExpiresAt.Format("2006-01-02 15:04:05"))
		},
	}
	return c
}

func newLogoutCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "logout",
		Short: "Logout and invalidate session",
		Run: func(cmd *cobra.Command, args []string) {
			tokenFile := getTokenFile()
			tokenBytes, err := os.ReadFile(tokenFile)
			if err != nil {
				fmt.Println("Not logged in")
				return
			}

			central, err := app.Config()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			am, err := getAuthManager(central)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			defer func() { _ = am.Close() }()

			if err := am.Logout(string(tokenBytes)); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			// Remove token file
			// Remove token file (best-effort)
			_ = os.Remove(tokenFile)
			fmt.Println("Logged out successfully")
		},
	}
	return c
}

func getAuthManager(cfg *config.Config) (*auth.AuthManager, error) {
	return getAuthManagerFromConfig(cfg)
}

func getTokenFile() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".ztap", "session.token")
}

// CheckAuth checks if the current session has permission for an action
func CheckAuth(perm auth.Permission) error {
	tokenFile := getTokenFile()
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return errors.New("not authenticated: please run 'ztap login'")
	}

	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	am, err := getAuthManager(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = am.Close() }()

	return am.HasPermission(string(tokenBytes), perm)
}
