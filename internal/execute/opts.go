package execute

type Options struct {
	BulkSMSConf     BulkSMSConfig
	MailConf        MailConfig
	ExecConf        ExecConfig
	SignedURLSecret string
	SignedURLTTL    int
}
