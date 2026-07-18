package execute

type Options struct {
	BulkSMSConf     BulkSMSConfig
	MailConf        MailConfig
	SignedURLSecret string
	SignedURLTTL    int
}
