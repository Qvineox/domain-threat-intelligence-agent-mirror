package jobEntities

import (
	"net"
	"slices"
)

type OpenSourceScanJob struct {
	Job

	Providers []SupportedOSSProvider
}

func (j *OpenSourceScanJob) CalculateTargets() []OSSTarget {
	var exceptedHosts = make([]string, 0, len(j.Exceptions))
	for _, v := range j.Exceptions {
		switch v.Type {
		case HOST_TYPE_CIDR:
			ips, err := getHostsFromCIDR(v.Host)
			if err != nil {
				continue
			}

			exceptedHosts = append(exceptedHosts, ips...)
		default:
			exceptedHosts = append(exceptedHosts, v.Host)
		}
	}

	var targetHosts = make([]Target, 0, len(j.Targets))
	for _, v := range j.Targets {
		switch v.Type {
		case HOST_TYPE_CIDR:
			ips, err := getHostsFromCIDR(v.Host)
			if err != nil {
				continue
			}

			for _, h := range ips {
				targetHosts = append(targetHosts, Target{
					Host: h,
					Type: v.Type,
				})
			}
		default:
			targetHosts = append(targetHosts, Target{
				Host: v.Host,
				Type: v.Type,
			})
		}
	}

	var hosts = make([]Target, 0, len(j.Targets))
	if len(exceptedHosts) > 0 {
		for _, v := range targetHosts {
			if !slices.Contains(exceptedHosts, v.Host) {
				hosts = append(hosts, v)
			}
		}
	} else {
		hosts = targetHosts
	}

	var tasks = make([]OSSTarget, 0, len(hosts))
	for _, h := range hosts {
		tasks = append(tasks, NewOSSTasksFromTarget(h, j.Providers)...)
	}

	return tasks
}

func getHostsFromCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// if net == 32 (no broadcast or network)
	if len(ips) <= 1 {
		return ips, nil
	}

	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
