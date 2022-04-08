package runner

import (
	"github.com/ZhuriLab/Starmap/pkg/passive"
	"github.com/ZhuriLab/Starmap/pkg/resolve"
	"github.com/ZhuriLab/Starmap/pkg/util"
	"net"
	"strings"
)

// initializePassiveEngine creates the passive engine and loads sources etc
func (r *Runner) initializePassiveEngine() {
	var sources, exclusions []string

	if len(r.options.ExcludeSources) > 0 {
		exclusions = r.options.ExcludeSources
	} else {
		exclusions = append(exclusions, r.options.YAMLConfig.ExcludeSources...)
	}

	switch {
	// Use all sources if asked by the user
	case r.options.All:
		sources = append(sources, r.options.YAMLConfig.AllSources...)
	// If only recursive sources are wanted, use them only.
	case r.options.OnlyRecursive:
		sources = append(sources, r.options.YAMLConfig.Recursive...)
	// Otherwise, use the CLI/YAML sources
	default:
		if len(r.options.Sources) == 0 {
			sources = append(sources, r.options.YAMLConfig.Sources...)
		} else {
			sources = r.options.Sources
		}
	}
	r.passiveAgent = passive.New(sources, exclusions)
}

// initializeActiveEngine creates the resolver used to resolve the found subdomains
func (r *Runner) initializeActiveEngine() error {
	var resolvers []string

	// If the file has been provided, read resolvers from the file
	if r.options.ResolverList != "" {
		var err error
		resolvers, err = loadFromFile(r.options.ResolverList)
		if err != nil {
			return err
		}
	}

	if len(r.options.Resolvers) > 0 {
		resolvers = append(resolvers, r.options.Resolvers...)
	} else if r.options.DNS == "in" {
		resolvers = append(resolvers, resolve.DefaultResolvers...)
	} else if r.options.DNS == "cn" {
		resolvers = append(resolvers, resolve.DefaultResolversCN...)
	} else if r.options.DNS == "all" {
		resolvers = append(resolve.DefaultResolvers, resolve.DefaultResolversCN...)
	} else if r.options.DNS == "conf" {
		resolvers = append(resolvers, r.options.YAMLConfig.Resolvers...)
	}

	resolvers = util.RemoveDuplicateElement(resolvers)

	// Add default 53 UDP port if missing
	for i, resolver := range resolvers {
		if !strings.Contains(resolver, ":") {
			resolvers[i] = net.JoinHostPort(resolver, "53")
		}
	}

	r.Resolvers = resolvers

	//r.resolverClient = resolve.New()
	//var err error
	//r.resolverClient.DNSClient, err = dnsx.New(dnsx.Options{BaseResolvers: resolvers, MaxRetries: 5})
	//if err != nil {
	//	return nil
	//}

	return nil
}
