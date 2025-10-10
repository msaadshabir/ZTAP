package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"text/tabwriter"

	"ztap/pkg/auth"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users and authentication",
	Long:  `Create, list, and manage users for ZTAP authentication`,
}

var createUserCmd = &cobra.Command{
	Use:   "create <username>",
	Short: "Create a new user",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		role, _ := cmd.Flags().GetString("role")

		// Get auth manager
		am, err := getAuthManager()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

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

var listUsersCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	Run: func(cmd *cobra.Command, args []string) {
		am, err := getAuthManager()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		users := am.ListUsers()
		if len(users) == 0 {
			fmt.Println("No users found")
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "USERNAME\tROLE\tENABLED\tCREATED\tLAST LOGIN")
		fmt.Fprintln(w, "--------\t----\t-------\t-------\t----------")

		for _, user := range users {
			lastLogin := "Never"
			if !user.LastLogin.IsZero() {
				lastLogin = user.LastLogin.Format("2006-01-02 15:04")
			}

			enabled := "Yes"
			if !user.Enabled {
				enabled = "No"
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				user.Username,
				user.Role,
				enabled,
				user.CreatedAt.Format("2006-01-02"),
				lastLogin,
			)
		}
		w.Flush()
	},
}

var changePasswordCmd = &cobra.Command{
	Use:   "change-password <username>",
	Short: "Change user password",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]

		am, err := getAuthManager()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

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

var disableUserCmd = &cobra.Command{
	Use:   "disable <username>",
	Short: "Disable a user account",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]

		am, err := getAuthManager()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if err := am.DisableUser(username); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("User '%s' disabled\n", username)
	},
}

var enableUserCmd = &cobra.Command{
	Use:   "enable <username>",
	Short: "Enable a user account",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]

		am, err := getAuthManager()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if err := am.EnableUser(username); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("User '%s' enabled\n", username)
	},
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate and create a session",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Print("Username: ")
		var username string
		fmt.Scanln(&username)

		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Printf("Error reading password: %v\n", err)
			os.Exit(1)
		}

		am, err := getAuthManager()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		session, err := am.Authenticate(username, string(passwordBytes))
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

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout and invalidate session",
	Run: func(cmd *cobra.Command, args []string) {
		tokenFile := getTokenFile()
		tokenBytes, err := os.ReadFile(tokenFile)
		if err != nil {
			fmt.Println("Not logged in")
			return
		}

		am, err := getAuthManager()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if err := am.Logout(string(tokenBytes)); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		// Remove token file
		os.Remove(tokenFile)
		fmt.Println("Logged out successfully")
	},
}

func init() {
	createUserCmd.Flags().StringP("role", "r", "operator", "User role (admin, operator, viewer)")

	userCmd.AddCommand(createUserCmd)
	userCmd.AddCommand(listUsersCmd)
	userCmd.AddCommand(changePasswordCmd)
	userCmd.AddCommand(disableUserCmd)
	userCmd.AddCommand(enableUserCmd)
	userCmd.AddCommand(loginCmd)
	userCmd.AddCommand(logoutCmd)

	rootCmd.AddCommand(userCmd)
}

func getAuthManager() (*auth.AuthManager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	dbPath := filepath.Join(homeDir, ".ztap", "users.json")
	return auth.NewAuthManager(dbPath)
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
		return fmt.Errorf("not authenticated: please run 'ztap login'")
	}

	am, err := getAuthManager()
	if err != nil {
		return err
	}

	return am.HasPermission(string(tokenBytes), perm)
}
