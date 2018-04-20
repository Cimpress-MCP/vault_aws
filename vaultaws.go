package main

import (
	"fmt"
	"os"
	"path"
	"reflect"
	"strconv"
	"time"

	"github.com/alecthomas/kingpin"
	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
	"github.com/davecgh/go-spew/spew"
	"github.com/fatih/color"
	"github.com/go-ini/ini"
	"github.com/hashicorp/vault/api"
	homedir "github.com/mitchellh/go-homedir"
)

var (
	debugEnabled = false
	version      = "v1.0"
	date         = "unknown"
	dateFormat   = "2006-01-02 15:04:05"
)

type listOptions struct {
	User     string
	Password string
	VaultURL string
	Debug    bool
}
type keyOptions struct {
	User     string
	Password string
	VaultURL string
	Debug    bool
	Profile  string
	Region   string
	Role     string
}

func init() {
	log.SetHandler(cli.Default)
}

func main() {
	fmt.Println()
	defer fmt.Println()

	// initialize command line arguments
	var app = kingpin.New("vaultaws", "Creates local AWS api keys while authenticating to Vault")
	var listCmd = app.Command("list", "List available roles in Vault")
	var authCmd = app.Command("auth", "Generate a new authentication key")
	var refreshCmd = app.Command("renew", "Renew an existing keypair")

	var userName = app.Flag("user", "Username to authenticate to vault").Short('u').Required().String()
	var passwordPtr = app.Flag("password", "Password for user").Required().Short('p').String()

	var profileName = authCmd.Flag("profile", "AWS profile name to manage").Default("default").String()
	var region = authCmd.Flag("region", "Region to configure your keys for").Short('r').Default("us-east-1").String()
	var role = authCmd.Flag("role", "Rollname to request from Vault").Required().String()

	var debugPtr = app.Flag("debug", "enable debugging").Bool()
	var vaultAddrPtr = app.Flag("addr", "Vault Address to authenticate with").String()

	var refreshProfile = refreshCmd.Flag("profile", "AWS Profile to refresh").Required().String()

	debugEnabled = *debugPtr

	app.Version(fmt.Sprintf("%v, built at %v", version, date))
	app.VersionFlag.Short('v')
	app.HelpFlag.Short('h')

	var vaultURL string
	if *vaultAddrPtr == "" {
		vaultURL = os.Getenv("VAULT_ADDR")
		if vaultURL == "" {
			log.Fatal("Error, must set VAULT_ADDR to your Vault URL within your environment.")
			os.Exit(1)
		}
	} else {
		vaultURL = *vaultAddrPtr
	}

	/*
		var password string
		// if user did not specify password, ask them for it, hiding typing.
		if passwordPtr == nil {
			fmt.Print("Please enter your password: ")
			bytePassword, err := terminal.ReadPassword(syscall.Stdin)
			if err != nil {
				log.WithError(err).Errorf(color.New(color.Bold).Sprintf("Could not read password."))
				terminate(1)
				return
			}
			password = string(bytePassword)
		} else {
			password = *passwordPtr
		}
	*/

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case listCmd.FullCommand():
		var options = listOptions{
			User:     *userName,
			Password: *passwordPtr,
			VaultURL: vaultURL,
			Debug:    *debugPtr,
		}
		if err := listRoles(options); err != nil {
			log.WithError(err).Errorf(color.New(color.Bold).Sprintf("Could not obtain list from Vault."))
			terminate(1)
			return
		}
	case authCmd.FullCommand():
		var options = keyOptions{
			User:     *userName,
			Password: *passwordPtr,
			VaultURL: vaultURL,
			Debug:    *debugPtr,
			Profile:  *profileName,
			Region:   *region,
			Role:     *role,
		}

		if err := getAWSKeys(options); err != nil {
			log.WithError(err).Errorf(color.New(color.Bold).Sprintf("Could not obtain aws keys from Vault."))
			terminate(1)
			return
		}
	case refreshCmd.FullCommand():
		var options = keyOptions{
			User:     *userName,
			Password: *passwordPtr,
			Profile:  *refreshProfile,
			VaultURL: vaultURL,
		}
		renewToken(options)
	}

}

func terminate(status int) {
	os.Exit(status)
}

type vaultAuthOptions struct {
	Username string
	Password string
	URL      string
}

// returned token string and error code, if any
func getClient(config vaultAuthOptions) (*api.Client, string, error) {
	// create config for connection
	vaultCFG := api.DefaultConfig()
	vaultCFG.Address = config.URL

	log.Debugf("Attempting to authenticate user %s to vault %s", config.Username, config.URL)
	// create client
	vClient, err := api.NewClient(vaultCFG)
	if err != nil {
		log.WithError(err).Errorf(color.New(color.Bold).Sprintf("Could not connect to Vault at %s.", config.URL))
		terminate(1)
		return nil, "", err
	}

	sys := vClient.Sys()
	sealStatus, _ := sys.SealStatus()
	if sealStatus.Sealed == true {
		log.Fatal("Error, Vault is sealed.  We cannot authenticate at this time.")
		terminate(1)
		return nil, "", nil
	}

	log.Infof("Requesting Vault authentication for user %s", config.Username)
	authOptions := map[string]interface{}{
		"password": config.Password,
	}

	loginPath := fmt.Sprintf("auth/userpass/login/%s", config.Username)
	secret, err := vClient.Logical().Write(loginPath, authOptions)
	if err != nil {
		log.WithError(err).Errorf(color.New(color.Bold).Sprintf("Could not authenticate user %s", config.Username))
		terminate(1)
		return nil, "", nil
	}

	vClient.SetToken(secret.Auth.ClientToken)

	log.Info("Authentication Success")

	return vClient, secret.Auth.ClientToken, nil
}

func listRoles(options listOptions) error {
	if options.Debug {
		log.SetLevel(log.DebugLevel)
	}

	var authOptions = vaultAuthOptions{
		Username: options.User,
		Password: options.Password,
		URL:      options.VaultURL,
	}
	vClient, _, err := getClient(authOptions)
	if err != nil {
		log.WithError(err).Errorf(color.New(color.Bold).Sprint("Could not get token from Vault"))
		terminate(1)
		return err
	}

	secret, err := vClient.Logical().List("/aws/roles")
	if err != nil {
		return err
	}

	keys := reflect.ValueOf(secret.Data["keys"])
	roles := make([]string, keys.Len())
	for i := 0; i < keys.Len(); i++ {
		roleName := fmt.Sprintf("%s", keys.Index(i))
		roles[i] = roleName
	}

	log.Info("Available roles in Vault are:")
	for _, role := range roles {
		log.Infof("\t%s", role)
	}

	return nil
}

type awsConfigOptions struct {
	AccessID  string `ini:"aws_access_key_id"`
	SecretKey string `ini:"aws_secret_access_key"`
	Expires   string `ini:"expires_on"`
	Role      string `ini:"vault_role"`
	Token     string `ini:"vault_token"`
	LeaseID   string `ini:"lease_id"`
}

func writeAWSConfig(profile string, region string, options awsConfigOptions) error {
	userDir, err := homedir.Dir()
	if err != nil {
		log.WithError(err).Error(color.New(color.Bold).Sprint("Could not load users home directory."))
		terminate(1)
		return err
	}

	// write secrets to AWS credential file
	awsCredFile := path.Join(userDir, ".aws")
	awsCredFile = path.Join(awsCredFile, "credentials")

	credCfg, err := ini.Load(awsCredFile)
	if err != nil {
		log.WithError(err).Errorf(color.New(color.Bold).Sprint("Could read AWS credential file at %s", awsCredFile))
		terminate(1)
		return err
	}

	credCfg.Section(profile).Key("aws_access_key_id").SetValue(options.AccessID)
	credCfg.Section(profile).Key("aws_secret_access_key").SetValue(options.SecretKey)
	credCfg.Section(profile).Key("expires_on").SetValue(options.Expires)
	credCfg.Section(profile).Key("vault_role").SetValue(options.Role)
	credCfg.Section(profile).Key("vault_token").SetValue(options.Token)
	credCfg.Section(profile).Key("lease_id").SetValue(options.LeaseID)
	credCfg.SaveTo(awsCredFile)

	// write config to AWS config file
	awsConfigFile := path.Join(userDir, ".aws")
	awsConfigFile = path.Join(awsConfigFile, "config")
	cfg, err := ini.Load(awsConfigFile)
	if err != nil {
		log.WithError(err).Errorf(color.New(color.Bold).Sprint("Could load AWS profile file at %s", awsCredFile))
		terminate(1)
		return err
	}
	cfg.Section(profile).Key("region").SetValue(region)
	cfg.SaveTo(awsConfigFile)

	log.Infof("updated AWS profile credentials for profile %s in %s", profile, awsCredFile)

	return nil
}

func readAWSConfig(profile string) (*awsConfigOptions, error) {
	userDir, err := homedir.Dir()
	if err != nil {
		log.WithError(err).Error(color.New(color.Bold).Sprint("Could not load users home directory."))
		terminate(1)
		return nil, err
	}

	// write secrets to AWS credential file
	awsCredFile := path.Join(userDir, ".aws")
	awsCredFile = path.Join(awsCredFile, "credentials")

	cfg, err := ini.Load(awsCredFile)

	config := new(awsConfigOptions)
	err = cfg.Section(profile).MapTo(config)
	if err != nil {
		log.WithError(err).Error(color.New(color.Bold).Sprint("Could not find profile %s in your AWS Configuration.", profile))
		terminate(1)
		return nil, err
	}

	return config, err
}

func getAWSKeys(options keyOptions) error {
	if options.Debug {
		log.SetLevel(log.DebugLevel)
	}

	var authOptions = vaultAuthOptions{
		Username: options.User,
		Password: options.Password,
		URL:      options.VaultURL,
	}

	vClient, token, err := getClient(authOptions)
	if err != nil {
		log.WithError(err).Errorf(color.New(color.Bold).Sprint("Could not get token from Vault"))
		terminate(1)
		return err
	}

	// ask Vault for AWS credentials

	vault := vClient.Logical()
	rolePath := fmt.Sprintf("/aws/creds/%s", options.Role)
	s, err := vault.Read(rolePath)
	if err != nil {
		log.WithError(err).Errorf(color.New(color.Bold).Sprint("Could read role %s from Vault", options.Role))
		terminate(1)
		return err
	}

	if options.Debug {
		spew.Dump(s)
	}

	expireStr := fmt.Sprintf("%d", s.Data["LeaseDuration"])
	leaseID := fmt.Sprintf("%s", s.LeaseID)
	expireDuration, _ := strconv.Atoi(expireStr)
	expirationTime := time.Now().Local().Add(time.Second + time.Duration(expireDuration))

	var configFileOptions = awsConfigOptions{
		AccessID:  fmt.Sprintf("%s", s.Data["access_key"]),
		SecretKey: fmt.Sprintf("%s", s.Data["secret_key"]),
		Expires:   expirationTime.Format(dateFormat),
		Role:      options.Role,
		Token:     token,
		LeaseID:   leaseID,
	}

	err = writeAWSConfig(options.Profile, options.Region, configFileOptions)
	if err != nil {
		terminate(1)
		return err
	}

	log.Infof("Your new keys are ready to use and expire on %s.", expirationTime)

	return nil
}

func renewToken(options keyOptions) error {
	if options.Debug {
		log.SetLevel(log.DebugLevel)
	}

	config, err := readAWSConfig(options.Profile)
	if err != nil {
		log.WithError(err).Errorf(color.New(color.Bold).Sprint("Could not read profile %s from your AWS Configuration", options.Profile))
		terminate(1)
		return err
	}

	log.Infof("Found existing lease, currently expires on %s", config.Expires)
	leaseT, err := time.Parse(dateFormat, config.Expires)
	if err != nil {
		log.WithError(err).Errorf(color.New(color.Bold).Sprintf("Could not read date from AWS config, date given was %s", config.Expires))
		terminate(1)
		return err
	}

	now := time.Now()
	if leaseT.Before(now) {
		log.Error("Error, your lease has expired.  You will need to reauth with Vault for new keys.")
		terminate(1)
		return err
	}

	var authOptions = vaultAuthOptions{
		Username: options.User,
		Password: options.Password,
		URL:      options.VaultURL,
	}

	vClient, _, err := getClient(authOptions)
	if err != nil {
		log.WithError(err).Errorf(color.New(color.Bold).Sprint("Could not get token from Vault"))
		terminate(1)
		return err
	}

	leasePayloadOptions := map[string]interface{}{
		"lease_id":  config.LeaseID,
		"increment": 27600,
	}

	s, err := vClient.Logical().Write("/sys/leases/renew", leasePayloadOptions)
	if err != nil {
		log.WithError(err).Errorf(color.New(color.Bold).Sprint("Could not renew lease %s from vault", config.LeaseID))
		terminate(1)
		return err
	}

	expireStr := fmt.Sprintf("%d", s.Data["LeaseDuration"])
	leaseID := fmt.Sprintf("%s", s.LeaseID)
	expireDuration, _ := strconv.Atoi(expireStr)
	expirationTime := time.Now().Local().Add(time.Second + time.Duration(expireDuration))

	var configFileOptions = awsConfigOptions{
		AccessID:  fmt.Sprintf("%s", s.Data["access_key"]),
		SecretKey: fmt.Sprintf("%s", s.Data["secret_key"]),
		Expires:   expirationTime.Format(dateFormat),
		Role:      options.Role,
		Token:     config.Token,
		LeaseID:   leaseID,
	}

	err = writeAWSConfig(options.Profile, options.Region, configFileOptions)

	return nil
}
