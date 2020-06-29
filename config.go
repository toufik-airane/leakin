package main

type configType struct {
	Secrets map[string]string
}

var configFile string = `
secrets:
  aws_access_key_id: (?i)(?:A3T|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[\w-_]{12,}
  aws_patterns: (?i)(?:accesskeyid|secretaccesskey|aws_access_key_id|aws_secret_access_key)
  slack_api_token: (xox[aboprs]-([0-9a-zA-Z-]{8,})?)
  slack_webhook_url: (hooks.slack.com\/services\/T[A-Z0-9]{8}\/B[A-Z0-9]{8}\/[a-zA-Z0-9]{1,})
  aws_s3: ([a-zA-Z0-9_-]+.s3.[a-z0-9_-]+.amazonaws.com)
  domain: http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))[^><'\" \n)]+
  google_patterns: (?i)(?:google_client_id|google_client_secret|google_client_token)
  artifactory: (artifactory.{0,50}(\\\"|')?[a-zA-Z0-9=]{112}(\\\"|')?)
  authorization_basic: (basic\s*[a-zA-Z0-9=:_\+\/-]+)
  authorization_bearer: (bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+)
  azure_blob: (http(?:s)://.[^><'\" \n\\)]+.blob.core.windows.net/.[^><'\" \n/)]+./)
  codeclimate: (codeclima.{0,50}(\\\"|')?[0-9a-f]{64}(\\\"|')?)
  digitalocean_space: (http(?:s)://[^><\\.'\" \n\\)]+.[^><\\.'\" \n\\)]+.[^><\\.'\" \n\\)]+.digitaloceanspaces.com)
  facebook_access_token: (EAACEdEose0cBA[0-9A-Za-z]+)
  facebook_client_id: (facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"]
  facebook_oauth: ([f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s])
  facebook_secret_key: (facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}['\"]
  gcp_api_key: (AIza[0-9A-Za-z-_]{35})
  gcp_client_secret: ("client_secret":"[\w-]{24}")
  gcp_service_account: ("type":"service_account")
  generic_secret: (?i)(secret.{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s])
  github: (github(.{0,20})?(?-i)['\"][0-9a-zA-Z]{35,40}['\"])
  github_access_token: \[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*
  google_captcha: (6L[0-9A-Za-z-_]{38})
  google_oauth: (ya29\.[0-9A-Za-z\-_]+)
  google_url: ([0-9]{12}-[a-z0-9]{32}.apps.googleusercontent.com)
  heroku_api_key: (HEROKU_API_KEY|HEROKU_API_TOKEN|HEROKU_API_SECRET|heroku_api_key|heroku_api_token|heroku_api_secret|heroku_key|HEROKU_TOKEN|HEROKU_AUTH|heroku_auth|herokuAuth|heroku_auth_token)[\W|\s]{1,}([0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12})\W
  heroku_api_key_api_key: ([h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})
  hockeyapp: hockey.{0,50}(\\\"|')?[0-9a-f]{32}(\\\"|')?
  json_web1_token: (eyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,})
  linkedin_client_id: (linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"])
  linkedin_secret_key: (linkedin(.{0,20})?['\"][0-9a-z]{16}['\"])
  mailchimp: (W(?:[a-f0-9]{32}(-us[0-9]{1,2}))\W)
  mailgun: (key-[0-9a-f]{32})
  mailgun_api_key: key-[0-9a-zA-Z]{32}
  npm_token: ([\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})
  nuget_api_key: (oy2[a-z0-9]{43})
  outlook_team: (https\\://outlook\\.office.com/webhook/[0-9a-f-]{36}\\@)
  paypal: \[\W]{1,2}([E][A-Z]{1}[a-zA-Z0-9_-]{78})[\W]{1,2}$
  paypal_braintree_access_token: (access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})
  private_key: (?i)-----(?:(?:BEGIN|END) )(?:(?:EC|PGP|DSA|RSA|OPENSSH).)?PRIVATE.KEY(.BLOCK)?-----
  sauce_token: (sauce.{0,50}(\\\"|')?[0-9a-f-]{36}(\\\"|')?)
  sendgrid_api_key: (SG\.[\w-]{16,32}\.[\w-]{16,64})
  sonarqube_docs_api_key: (sonar.{0,50}(\\\"|')?[0-9a-f]{40}(\\\"|')?)
  square_app_secret: (sq0[a-z]{3}-[0-9A-Za-z\-_]{20,50})
  ssh_password: (sshpass -p.*['|\\\"])
  stripe_restricted_api: (rk_live_[0-9a-zA-Z]{24,34})
  stripe_standard_api: (sk_live_[0-9a-zA-Z]{24,34})
  twitter: ([\W]{1,2}([a-zA-Z0-9]{50})[\W]{1,2}$)
  twitter_client_id: (twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"])
  twitter_oauth: ([t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s])
  twitter_secret_key: twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"]
  apikey_patterns: (?i)apikey[:](?:["']?[\w-_|]+["']?)

  `

// Working
// ip_address: ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})
