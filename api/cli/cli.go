package cli

import (
	"errors"
	"log"
	"time"

	portainer "github.com/portainer/portainer/api"

	"os"
	"path/filepath"
	"strings"

	"gopkg.in/alecthomas/kingpin.v2"
)

// Service implements the CLIService interface
//Service 空结构体提供解析Flag方法
//满足portainer.CLIService接口
type Service struct{}

var (
	errInvalidEndpointProtocol       = errors.New("Invalid endpoint protocol: Portainer only supports unix://, npipe:// or tcp://")
	errSocketOrNamedPipeNotFound     = errors.New("Unable to locate Unix socket or named pipe")
	errInvalidSnapshotInterval       = errors.New("Invalid snapshot interval")
	errAdminPassExcludeAdminPassFile = errors.New("Cannot use --admin-password with --admin-password-file")
)

// ParseFlags parse the CLI flags and return a portainer.Flags struct
func (*Service) ParseFlags(version string) (*portainer.CLIFlags, error) {
	//设置Portainer CLI版本号
	//默认取portainer.APIVersion变量
	kingpin.Version(version)

	flags := &portainer.CLIFlags{
		//绑定的服务IP地址
		Addr: kingpin.Flag("bind", "Address and port to serve Portainer").Default(defaultBindAddress).Short('p').String(),
		//通道地址
		TunnelAddr: kingpin.Flag("tunnel-addr", "Address to serve the tunnel server").Default(defaultTunnelServerAddress).String(),
		//通道端口
		TunnelPort: kingpin.Flag("tunnel-port", "Port to serve the tunnel server").Default(defaultTunnelServerPort).String(),
		//网页网络资源路径
		Assets: kingpin.Flag("assets", "Path to the assets").Default(defaultAssetsDirectory).Short('a').String(),
		//存储目录
		Data:                      kingpin.Flag("data", "Path to the folder where the data is stored").Default(defaultDataDirectory).Short('d').String(),
		EndpointURL:               kingpin.Flag("host", "Endpoint URL").Short('H').String(),
		EnableEdgeComputeFeatures: kingpin.Flag("edge-compute", "Enable Edge Compute features").Bool(),
		NoAnalytics:               kingpin.Flag("no-analytics", "Disable Analytics in app (deprecated)").Bool(),
		TLS:                       kingpin.Flag("tlsverify", "TLS support").Default(defaultTLS).Bool(),
		TLSSkipVerify:             kingpin.Flag("tlsskipverify", "Disable TLS server verification").Default(defaultTLSSkipVerify).Bool(),
		TLSCacert:                 kingpin.Flag("tlscacert", "Path to the CA").Default(defaultTLSCACertPath).String(),
		TLSCert:                   kingpin.Flag("tlscert", "Path to the TLS certificate file").Default(defaultTLSCertPath).String(),
		TLSKey:                    kingpin.Flag("tlskey", "Path to the TLS key").Default(defaultTLSKeyPath).String(),
		SSL:                       kingpin.Flag("ssl", "Secure Portainer instance using SSL").Default(defaultSSL).Bool(),
		SSLCert:                   kingpin.Flag("sslcert", "Path to the SSL certificate used to secure the Portainer instance").Default(defaultSSLCertPath).String(),
		SSLKey:                    kingpin.Flag("sslkey", "Path to the SSL key used to secure the Portainer instance").Default(defaultSSLKeyPath).String(),
		SnapshotInterval:          kingpin.Flag("snapshot-interval", "Duration between each endpoint snapshot job").Default(defaultSnapshotInterval).String(),
		AdminPassword:             kingpin.Flag("admin-password", "Hashed admin password").String(),
		AdminPasswordFile:         kingpin.Flag("admin-password-file", "Path to the file containing the password for the admin user").String(),
		Labels:                    pairs(kingpin.Flag("hide-label", "Hide containers with a specific label in the UI").Short('l')),
		Logo:                      kingpin.Flag("logo", "URL for the logo displayed in the UI").String(),
		Templates:                 kingpin.Flag("templates", "URL to the templates definitions.").Short('t').String(),
	}
	//解析CLI命令
	kingpin.Parse()
	//处理非绝对路径
	//flags.Assets必须为绝对路径
	if !filepath.IsAbs(*flags.Assets) {
		//获取当前执行文件的绝对路径
		ex, err := os.Executable()
		if err != nil {
			panic(err)
		}
		*flags.Assets = filepath.Join(filepath.Dir(ex), *flags.Assets)
	}
	//返回CLI获取的参数
	return flags, nil
}

// ValidateFlags validates the values of the flags.
// 校验Flag有效性
//校验:
//端点
//快照间隔
func (*Service) ValidateFlags(flags *portainer.CLIFlags) error {
	//显示状态为Deprecation的命令相关详情
	displayDeprecationWarnings(flags)
	//检验端点地址
	err := validateEndpointURL(*flags.EndpointURL)
	if err != nil {
		return err
	}
	//校验快照间隙
	err = validateSnapshotInterval(*flags.SnapshotInterval)
	if err != nil {
		return err
	}
	//解决设置管理员密码同时使用管理员文件密码
	if *flags.AdminPassword != "" && *flags.AdminPasswordFile != "" {
		return errAdminPassExcludeAdminPassFile
	}

	return nil
}

func displayDeprecationWarnings(flags *portainer.CLIFlags) {
	//NoAnalytics 参数已弃用
	if *flags.NoAnalytics {
		log.Println("Warning: The --no-analytics flag has been kept to allow migration of instances running a previous version of Portainer with this flag enabled, to version 2.0 where enabling this flag will have no effect.")
	}
}

//检验端点是否有效
func validateEndpointURL(endpointURL string) error {
	if endpointURL != "" {
		//若端点前缀不包含""unix,tcp,npipe"则返回错误
		//反之包含则继续向下执行
		if !strings.HasPrefix(endpointURL, "unix://") && !strings.HasPrefix(endpointURL, "tcp://") && !strings.HasPrefix(endpointURL, "npipe://") {
			return errInvalidEndpointProtocol
		}
		//检查unix/npipe套接字是否存在
		if strings.HasPrefix(endpointURL, "unix://") || strings.HasPrefix(endpointURL, "npipe://") {
			socketPath := strings.TrimPrefix(endpointURL, "unix://")
			socketPath = strings.TrimPrefix(socketPath, "npipe://")
			//获取文件状态
			if _, err := os.Stat(socketPath); err != nil {
				//判断文件是否存在
				if os.IsNotExist(err) {
					return errSocketOrNamedPipeNotFound
				}
				return err
			}
		}
	}
	return nil
}

//校验快照时长
func validateSnapshotInterval(snapshotInterval string) error {
	if snapshotInterval != defaultSnapshotInterval {
		//解析字符串市场如（5s/5m/5h...）
		_, err := time.ParseDuration(snapshotInterval)
		if err != nil {
			return errInvalidSnapshotInterval
		}
	}
	return nil
}
