// +build !windows

package router

func RunAsService(handler func()) bool {
	return false
}
