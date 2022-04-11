package runner

import (
	"github.com/ZhuriLab/Starmap/pkg/passive"
	"github.com/ZhuriLab/Starmap/pkg/resolve"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
)

const banner = `
 ███████████████╗█████╗██████╗███╗   ███╗█████╗██████╗ 
 ██╔════╚══██╔══██╔══████╔══██████╗ ██████╔══████╔══██╗
 ███████╗  ██║  █████████████╔██╔████╔███████████████╔╝
 ╚════██║  ██║  ██╔══████╔══████║╚██╔╝████╔══████╔═══╝ 
 ███████║  ██║  ██║  ████║  ████║ ╚═╝ ████║  ████║     
 ╚══════╝  ╚═╝  ╚═╝  ╚═╚═╝  ╚═╚═╝     ╚═╚═╝  ╚═╚═╝
`

// Version is the current version of Starmap
const Version = `v0.0.7`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", aurora.Blue(banner))
	gologger.Print().Msgf("\t\t\t\t%s\n", aurora.Red(Version))
	gologger.Print().Msgf("\t\t\t%s\n\n", aurora.Green("https://github.com/ZhuriLab/Starmap"))

	gologger.Print().Msgf(aurora.Red("Use with caution. You are responsible for your actions").String())
	gologger.Print().Msgf(aurora.Red("Developers assume no liability and are not responsible for any misuse or damage.").String())
	gologger.Print().Msgf(aurora.Red("By using Starmap, you also agree to the terms of the APIs used.\n").String())
}

// normalRunTasks runs the normal startup tasks
func (options *Options) normalRunTasks() {
	configFile, err := UnmarshalRead(options.Config)
	if err != nil {
		gologger.Fatal().Msgf("Could not read configuration file %s: %s\n", options.Config, err)
	}

	// If we have a different version of subfinder installed
	// previously, use the new iteration of config file.

	if configFile.Version != Version {
		configFile.Sources = passive.DefaultSources
		configFile.AllSources = passive.DefaultAllSources
		configFile.Recursive = passive.DefaultRecursiveSources
		configFile.Version = Version

		err = configFile.MarshalWrite(options.Config)
		if err != nil {
			gologger.Fatal().Msgf("Could not update configuration file to %s: %s\n", options.Config, err)
		}
	}
	options.YAMLConfig = configFile
}


// firstRunTasks runs some housekeeping tasks done
// when the program is ran for the first time
func (options *Options) firstRunTasks() {
	// Create the configuration file and display information
	// about it to the user.
	config := Providers {
		// Use the default list of resolvers by marshaling it to the config
		Resolvers: resolve.DefaultResolvers,
		// Use the default list of passive sources
		Sources: passive.DefaultSources,
		// Use the default list of all passive sources
		AllSources: passive.DefaultAllSources,
		// Use the default list of recursive sources
		Recursive: passive.DefaultRecursiveSources,
		Version: Version,
	}

	err := config.MarshalWrite(options.Config)

	if err != nil {
		gologger.Fatal().Msgf("Could not write configuration file to %s: %s\n", options.Config, err)
	}
	options.YAMLConfig = config

	gologger.Info().Msgf("Configuration file saved to %s\n", options.Config)
}