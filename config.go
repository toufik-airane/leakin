package main

var configbyte = []byte(`
{
    "title": "Leakin",
    "checks": [
        {
            "title": "AWS API Gateway",
            "regex": "[0-9a-z]+.execute-api.[0-9a-z.-_]+.amazonaws.com",
            "severity": 1
        },
        {
            "title": "AWS ARN",
            "regex": "arn:aws:[a-z0-9-]+:[a-z]{2}-[a-z]+-[0-9]+:[0-9]+:.+",
            "severity": 1
        },
        {
            "title": "AWS Client ID",
            "regex": "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            "severity": 6
        },
        {
            "title": "AWS CloudFront",
            "regex": "[0-9a-z.-_]+.cloudfront.net",
            "severity": 1
        },
        {
            "title": "AWS EC2 External",
            "regex": "ec2-[0-9a-z.-_]+.compute(-1)?.amazonaws.com",
            "severity": 1
        },
        {
            "title": "AWS EC2 Internal",
            "regex": "[0-9a-z.-_]+.compute(-1)?.internal",
            "severity": 1
        },
        {
            "title": "AWS ELB",
            "regex": "[0-9a-z.-_]+.elb.[0-9a-z.-_]+.amazonaws.com",
            "severity": 1
        },
        {
            "title": "AWS ELB",
            "regex": "[0-9a-z.-_]+.elb.amazonaws.com",
            "severity": 1
        },
        {
            "title": "AWS ElasticCache",
            "regex": "[0-9a-z.-_]+.cache.amazonaws.com",
            "severity": 1
        },
        {
            "title": "AWS MWS key",
            "regex": "amzn.mws.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "severity": 8
        },
        {
            "title": "AWS RDS",
            "regex": "[0-9a-z.-_]+.rds.amazonaws.com",
            "severity": 1
        },
        {
            "title": "AWS S3 Bucket",
            "regex": "s3://[0-9a-z.-_/]+",
            "severity": 1
        },
        {
            "title": "AWS S3 Endpoint",
            "regex": "[0-9a-z.-_]+.s3-website[0-9a-z.-_]+.amazonaws.com",
            "severity": 1
        },
        {
            "title": "AWS S3 Endpoint",
            "regex": "[a-zA-Z0-9.-_]+.s3.[a-zA-Z0-9.-_]+.amazonaws.com",
            "severity": 1
        },
        {
            "title": "AWS Secret Key",
            "regex": "aws(.{0,20})?['\"][0-9a-z/+]{40}['\"]",
            "severity": 7
        },
        {
            "title": "Braintree API Key",
            "regex": "access_token$production$[0-9a-z]{16}$[0-9a-f]{32}",
            "severity": 9
        },
        {
            "title": "FCM_server_key",
            "regex": "(?i)(AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140})",
            "severity": "5"
        },
        {
            "title": "Facebook Access Token",
            "regex": "EAACEdEose0cBA[0-9a-z]+",
            "severity": 6
        },
        {
            "title": "Facebook Client ID",
            "regex": "(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"]",
            "severity": 1
        },
        {
            "title": "Facebook Secret Key",
            "regex": "(facebook|fb)(.{0,20})?['\"][0-9a-f]{32}['\"]",
            "severity": 7
        },
        {
            "title": "GitHub Token",
            "regex": "github(.{0,20})?['\"][0-9a-z]{35,40}['\"]",
            "severity": 9
        },
        {
            "title": "Google API Key",
            "regex": "AIza[0-9a-z-_]{35}",
            "severity": 7
        },
        {
            "title": "Google Cloud Platform API key",
            "regex": "(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z-_]{35}]['\"]",
            "severity": 9
        },
        {
            "title": "Google Oauth ID",
            "regex": "[0-9]+-[0-9a-z_]{32}.apps.googleusercontent.com",
            "severity": 5
        },
        {
            "title": "Heroku API Key",
            "regex": "heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
            "severity": 9
        },
        {
            "title": "LinkedIn Client ID",
            "regex": "linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]",
            "severity": 6
        },
        {
            "title": "LinkedIn Secret Key",
            "regex": "linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]",
            "severity": 7
        },
        {
            "title": "Mailchimp API Key",
            "regex": "[0-9a-f]{32}-us[0-9]{1,2}",
            "severity": 9
        },
        {
            "title": "Mailgun API Key",
            "regex": "key-[0-9a-z]{32}",
            "severity": 9
        },
        {
            "title": "PGP",
            "regex": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "severity": 10
        },
        {
            "title": "RKCS8",
            "regex": "-----BEGIN PRIVATE KEY-----",
            "severity": 10
        },
        {
            "title": "RSA",
            "regex": "-----BEGIN RSA PRIVATE KEY-----",
            "severity": 10
        },
        {
            "title": "SSH",
            "regex": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "severity": 10
        },
        {
            "title": "Slack Token",
            "regex": "xox[baprs]-([0-9a-z-]{10,48})",
            "severity": 9
        },
        {
            "title": "Square API Key",
            "regex": "sq0(atp|csp)-[0-9a-z-_]{22,43}",
            "severity": 9
        },
        {
            "title": "Stripe Public Live Key",
            "regex": "pk_live_[0-9a-z]{24}",
            "severity": 1
        },
        {
            "title": "Stripe Public Test Key",
            "regex": "pk_test_[0-9a-z]{24}",
            "severity": 1
        },
        {
            "title": "Stripe Secret Live Key",
            "regex": "(sk|rk)_live_[0-9a-z]{24}",
            "severity": 10
        },
        {
            "title": "Stripe Secret Test Key",
            "regex": "(sk|rk)_test_[0-9a-z]{24}",
            "severity": 5
        },
        {
            "title": "Telegram Secret",
            "regex": "d{5,}:A[0-9a-z_-]{34,34}",
            "severity": 7
        },
        {
            "title": "Trello URL",
            "regex": "https://trello.com/b/[0-9a-z]/[0-9a-z_-]+",
            "severity": 1
        },
        {
            "title": "Twilio API Key",
            "regex": "SK[0-9a-fA-F]{32}",
            "severity": 8
        },
        {
            "title": "Twitter Client ID",
            "regex": "twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"]",
            "severity": 6
        },
        {
            "title": "Twitter Secret Key",
            "regex": "twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"]",
            "severity": 7
        },
        {
            "title": "access_key_secret",
            "regex": "access[_-]?key[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "access_secret",
            "regex": "access[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "access_token",
            "regex": "access[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "account_sid",
            "regex": "account[_-]?sid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "admin_email",
            "regex": "admin[_-]?email(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "adzerk_api_key",
            "regex": "adzerk[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "algolia_admin_key_1",
            "regex": "algolia[_-]?admin[_-]?key[_-]?1(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "algolia_admin_key_2",
            "regex": "algolia[_-]?admin[_-]?key[_-]?2(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "algolia_admin_key_mcm",
            "regex": "algolia[_-]?admin[_-]?key[_-]?mcm(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "algolia_api_key",
            "regex": "algolia[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "algolia_api_key_mcm",
            "regex": "algolia[_-]?api[_-]?key[_-]?mcm(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "algolia_api_key_search",
            "regex": "algolia[_-]?api[_-]?key[_-]?search(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "algolia_search_api_key",
            "regex": "algolia[_-]?search[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "algolia_search_key",
            "regex": "algolia[_-]?search[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "algolia_search_key_1",
            "regex": "algolia[_-]?search[_-]?key[_-]?1(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "alias_pass",
            "regex": "alias[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "alicloud_access_key",
            "regex": "alicloud[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "alicloud_secret_key",
            "regex": "alicloud[_-]?secret[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "amazon_bucket_name",
            "regex": "amazon[_-]?bucket[_-]?name(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "amazon_secret_access_key",
            "regex": "amazon[_-]?secret[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "anaconda_token",
            "regex": "anaconda[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "android_docs_deploy_token",
            "regex": "android[_-]?docs[_-]?deploy[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ansible_vault_password",
            "regex": "ansible[_-]?vault[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "aos_key",
            "regex": "aos[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "aos_sec",
            "regex": "aos[_-]?sec(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "api_key",
            "regex": "api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "api_key_secret",
            "regex": "api[_-]?key[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "api_key_sid",
            "regex": "api[_-]?key[_-]?sid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "api_secret",
            "regex": "api[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "apiary_api_key",
            "regex": "apiary[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "apigw_access_token",
            "regex": "apigw[_-]?access[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "apikey_patterns",
            "regex": "(?i)apikey[:](?:['\"]?[a-zA-Z0-9-_|]+['\"]?)",
            "severity": "5"
        },
        {
            "title": "app_bucket_perm",
            "regex": "app[_-]?bucket[_-]?perm(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "app_report_token_key",
            "regex": "app[_-]?report[_-]?token[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "app_secrete",
            "regex": "app[_-]?secrete(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "app_token",
            "regex": "app[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "appclientsecret",
            "regex": "appclientsecret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "apple_id_password",
            "regex": "apple[_-]?id[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "argos_token",
            "regex": "argos[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "artifactory",
            "regex": "(artifactory.{0,50}(\"|')?[a-zA-Z0-9=]{112}(\"|')?)",
            "severity": "5"
        },
        {
            "title": "artifactory_key",
            "regex": "artifactory[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "artifacts_aws_access_key_id",
            "regex": "artifacts[_-]?aws[_-]?access[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "artifacts_aws_secret_access_key",
            "regex": "artifacts[_-]?aws[_-]?secret[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "artifacts_bucket",
            "regex": "artifacts[_-]?bucket(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "artifacts_key",
            "regex": "artifacts[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "artifacts_secret",
            "regex": "artifacts[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "assistant_iam_apikey",
            "regex": "assistant[_-]?iam[_-]?apikey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "auth0_api_clientsecret",
            "regex": "auth0[_-]?api[_-]?clientsecret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "auth0_client_secret",
            "regex": "auth0[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "auth_token",
            "regex": "auth[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "author_email_addr",
            "regex": "author[_-]?email[_-]?addr(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "author_npm_api_key",
            "regex": "author[_-]?npm[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "aws_access",
            "regex": "aws[_-]?access(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "aws_access_key",
            "regex": "aws[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "aws_access_key_id",
            "regex": "aws[_-]?access[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "aws_access_key_id",
            "regex": "(?:A3T|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[a-zA-Z0-9-_]{12,}",
            "severity": "5"
        },
        {
            "title": "aws_config_accesskeyid",
            "regex": "aws[_-]?config[_-]?accesskeyid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "aws_config_secretaccesskey",
            "regex": "aws[_-]?config[_-]?secretaccesskey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "aws_key",
            "regex": "aws[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "aws_patterns",
            "regex": "(?i)(?:accesskeyid|secretaccesskey|aws_access_key_id|aws_secret_access_key)",
            "severity": "5"
        },
        {
            "title": "aws_s3",
            "regex": "([a-zA-Z0-9_-]+.s3.[a-z0-9_-]+.amazonaws.com)",
            "severity": "5"
        },
        {
            "title": "aws_secret",
            "regex": "aws[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "aws_secret_access_key",
            "regex": "aws[_-]?secret[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "aws_secret_key",
            "regex": "aws[_-]?secret[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "aws_secrets",
            "regex": "aws[_-]?secrets(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "aws_ses_access_key_id",
            "regex": "aws[_-]?ses[_-]?access[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "aws_ses_secret_access_key",
            "regex": "aws[_-]?ses[_-]?secret[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "awsaccesskeyid",
            "regex": "awsaccesskeyid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "awscn_access_key_id",
            "regex": "awscn[_-]?access[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "awscn_secret_access_key",
            "regex": "awscn[_-]?secret[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "awssecretkey",
            "regex": "awssecretkey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "azure_blob",
            "regex": "(http(?:s)://.[^><'\" \n)]+.blob.core.windows.net/.[^><'\" \n/)]+./)",
            "severity": "5"
        },
        {
            "title": "b2_app_key",
            "regex": "b2[_-]?app[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "b2_bucket",
            "regex": "b2[_-]?bucket(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bintray_api_key",
            "regex": "bintray[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bintray_apikey",
            "regex": "bintray[_-]?apikey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bintray_gpg_password",
            "regex": "bintray[_-]?gpg[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bintray_key",
            "regex": "bintray[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bintray_token",
            "regex": "bintray[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bintraykey",
            "regex": "bintraykey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bluemix_api_key",
            "regex": "bluemix[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bluemix_auth",
            "regex": "bluemix[_-]?auth(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bluemix_pass",
            "regex": "bluemix[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bluemix_pass_prod",
            "regex": "bluemix[_-]?pass[_-]?prod(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bluemix_password",
            "regex": "bluemix[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bluemix_pwd",
            "regex": "bluemix[_-]?pwd(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bluemix_username",
            "regex": "bluemix[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "brackets_repo_oauth_token",
            "regex": "brackets[_-]?repo[_-]?oauth[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "browser_stack_access_key",
            "regex": "browser[_-]?stack[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "browserstack_access_key",
            "regex": "browserstack[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bucketeer_aws_access_key_id",
            "regex": "bucketeer[_-]?aws[_-]?access[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bucketeer_aws_secret_access_key",
            "regex": "bucketeer[_-]?aws[_-]?secret[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "built_branch_deploy_key",
            "regex": "built[_-]?branch[_-]?deploy[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bundlesize_github_token",
            "regex": "bundlesize[_-]?github[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bx_password",
            "regex": "bx[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "bx_username",
            "regex": "bx[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cache_s3_secret_key",
            "regex": "cache[_-]?s3[_-]?secret[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cargo_token",
            "regex": "cargo[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cattle_access_key",
            "regex": "cattle[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cattle_agent_instance_auth",
            "regex": "cattle[_-]?agent[_-]?instance[_-]?auth(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cattle_secret_key",
            "regex": "cattle[_-]?secret[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "censys_secret",
            "regex": "censys[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "certificate_password",
            "regex": "certificate[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cf_password",
            "regex": "cf[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cheverny_token",
            "regex": "cheverny[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "chrome_client_secret",
            "regex": "chrome[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "chrome_refresh_token",
            "regex": "chrome[_-]?refresh[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ci_deploy_password",
            "regex": "ci[_-]?deploy[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ci_project_url",
            "regex": "ci[_-]?project[_-]?url(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ci_registry_user",
            "regex": "ci[_-]?registry[_-]?user(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ci_server_name",
            "regex": "ci[_-]?server[_-]?name(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ci_user_token",
            "regex": "ci[_-]?user[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "claimr_database",
            "regex": "claimr[_-]?database(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "claimr_db",
            "regex": "claimr[_-]?db(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "claimr_superuser",
            "regex": "claimr[_-]?superuser(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "claimr_token",
            "regex": "claimr[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cli_e2e_cma_token",
            "regex": "cli[_-]?e2e[_-]?cma[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "client_secret",
            "regex": "client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "clojars_password",
            "regex": "clojars[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloud_api_key",
            "regex": "cloud[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudant_archived_database",
            "regex": "cloudant[_-]?archived[_-]?database(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudant_audited_database",
            "regex": "cloudant[_-]?audited[_-]?database(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudant_database",
            "regex": "cloudant[_-]?database(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudant_instance",
            "regex": "cloudant[_-]?instance(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudant_order_database",
            "regex": "cloudant[_-]?order[_-]?database(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudant_parsed_database",
            "regex": "cloudant[_-]?parsed[_-]?database(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudant_password",
            "regex": "cloudant[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudant_processed_database",
            "regex": "cloudant[_-]?processed[_-]?database(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudant_service_database",
            "regex": "cloudant[_-]?service[_-]?database(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudflare_api_key",
            "regex": "cloudflare[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudflare_auth_email",
            "regex": "cloudflare[_-]?auth[_-]?email(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudflare_auth_key",
            "regex": "cloudflare[_-]?auth[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudflare_email",
            "regex": "cloudflare[_-]?email(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudinary_url",
            "regex": "cloudinary[_-]?url(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cloudinary_url_staging",
            "regex": "cloudinary[_-]?url[_-]?staging(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "clu_repo_url",
            "regex": "clu[_-]?repo[_-]?url(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "clu_ssh_private_key_base64",
            "regex": "clu[_-]?ssh[_-]?private[_-]?key[_-]?base64(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cn_access_key_id",
            "regex": "cn[_-]?access[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cn_secret_access_key",
            "regex": "cn[_-]?secret[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cocoapods_trunk_email",
            "regex": "cocoapods[_-]?trunk[_-]?email(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cocoapods_trunk_token",
            "regex": "cocoapods[_-]?trunk[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "codacy_project_token",
            "regex": "codacy[_-]?project[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "codeclimate",
            "regex": "(codeclima.{0,50}(\"|')?[0-9a-f]{64}(\"|')?)",
            "severity": "5"
        },
        {
            "title": "codeclimate_repo_token",
            "regex": "codeclimate[_-]?repo[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "codecov_token",
            "regex": "codecov[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "coding_token",
            "regex": "coding[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "conekta_apikey",
            "regex": "conekta[_-]?apikey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "consumer_key",
            "regex": "consumer[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "consumerkey",
            "regex": "consumerkey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "contentful_access_token",
            "regex": "contentful[_-]?access[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "contentful_cma_test_token",
            "regex": "contentful[_-]?cma[_-]?test[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "contentful_integration_management_token",
            "regex": "contentful[_-]?integration[_-]?management[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "contentful_management_api_access_token",
            "regex": "contentful[_-]?management[_-]?api[_-]?access[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "contentful_management_api_access_token_new",
            "regex": "contentful[_-]?management[_-]?api[_-]?access[_-]?token[_-]?new(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "contentful_php_management_test_token",
            "regex": "contentful[_-]?php[_-]?management[_-]?test[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "contentful_test_org_cma_token",
            "regex": "contentful[_-]?test[_-]?org[_-]?cma[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "contentful_v2_access_token",
            "regex": "contentful[_-]?v2[_-]?access[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "conversation_password",
            "regex": "conversation[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "conversation_username",
            "regex": "conversation[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cos_secrets",
            "regex": "cos[_-]?secrets(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "coveralls_api_token",
            "regex": "coveralls[_-]?api[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "coveralls_repo_token",
            "regex": "coveralls[_-]?repo[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "coveralls_token",
            "regex": "coveralls[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "coverity_scan_token",
            "regex": "coverity[_-]?scan[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "cypress_record_key",
            "regex": "cypress[_-]?record[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "danger_github_api_token",
            "regex": "danger[_-]?github[_-]?api[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "database_host",
            "regex": "database[_-]?host(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "database_name",
            "regex": "database[_-]?name(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "database_password",
            "regex": "database[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "database_port",
            "regex": "database[_-]?port(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "database_user",
            "regex": "database[_-]?user(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "database_username",
            "regex": "database[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "datadog_api_key",
            "regex": "datadog[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "datadog_app_key",
            "regex": "datadog[_-]?app[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "db_connection",
            "regex": "db[_-]?connection(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "db_database",
            "regex": "db[_-]?database(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "db_host",
            "regex": "db[_-]?host(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "db_password",
            "regex": "db[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "db_pw",
            "regex": "db[_-]?pw(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "db_user",
            "regex": "db[_-]?user(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "db_username",
            "regex": "db[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ddg_test_email",
            "regex": "ddg[_-]?test[_-]?email(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ddg_test_email_pw",
            "regex": "ddg[_-]?test[_-]?email[_-]?pw(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ddgc_github_token",
            "regex": "ddgc[_-]?github[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "deploy_password",
            "regex": "deploy[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "deploy_secure",
            "regex": "deploy[_-]?secure(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "deploy_token",
            "regex": "deploy[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "deploy_user",
            "regex": "deploy[_-]?user(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "dgpg_passphrase",
            "regex": "dgpg[_-]?passphrase(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "digitalocean_access_token",
            "regex": "digitalocean[_-]?access[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "digitalocean_space",
            "regex": "(http(?:s)://[^><.'\" \n)]+.[^><.'\" \n)]+.[^><.'\" \n)]+.digitaloceanspaces.com)",
            "severity": "5"
        },
        {
            "title": "digitalocean_ssh_key_body",
            "regex": "digitalocean[_-]?ssh[_-]?key[_-]?body(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "digitalocean_ssh_key_ids",
            "regex": "digitalocean[_-]?ssh[_-]?key[_-]?ids(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "docker_hub_password",
            "regex": "docker[_-]?hub[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "docker_key",
            "regex": "docker[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "docker_pass",
            "regex": "docker[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "docker_passwd",
            "regex": "docker[_-]?passwd(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "docker_password",
            "regex": "docker[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "docker_postgres_url",
            "regex": "docker[_-]?postgres[_-]?url(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "docker_token",
            "regex": "docker[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "dockerhub_password",
            "regex": "dockerhub[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "dockerhubpassword",
            "regex": "dockerhubpassword(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "domain",
            "regex": "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))[^><'\" \n)]+",
            "severity": "5"
        },
        {
            "title": "doordash_auth_token",
            "regex": "doordash[_-]?auth[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "dropbox_oauth_bearer",
            "regex": "dropbox[_-]?oauth[_-]?bearer(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "droplet_travis_password",
            "regex": "droplet[_-]?travis[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "dsonar_login",
            "regex": "dsonar[_-]?login(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "dsonar_projectkey",
            "regex": "dsonar[_-]?projectkey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "elastic_cloud_auth",
            "regex": "elastic[_-]?cloud[_-]?auth(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "elasticsearch_password",
            "regex": "elasticsearch[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "encryption_password",
            "regex": "encryption[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "end_user_password",
            "regex": "end[_-]?user[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "env_github_oauth_token",
            "regex": "env[_-]?github[_-]?oauth[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "env_heroku_api_key",
            "regex": "env[_-]?heroku[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "env_key",
            "regex": "env[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "env_secret",
            "regex": "env[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "env_secret_access_key",
            "regex": "env[_-]?secret[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "env_sonatype_password",
            "regex": "env[_-]?sonatype[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "eureka_awssecretkey",
            "regex": "eureka[_-]?awssecretkey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "exp_password",
            "regex": "exp[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "facebook_access_token",
            "regex": "(EAACEdEose0cBA[0-9A-Za-z]+)",
            "severity": "5"
        },
        {
            "title": "facebook_client_id",
            "regex": "(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"]",
            "severity": "5"
        },
        {
            "title": "facebook_secret_key",
            "regex": "(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}['\"]",
            "severity": "5"
        },
        {
            "title": "file_password",
            "regex": "file[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "firebase_api_json",
            "regex": "firebase[_-]?api[_-]?json(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "firebase_api_token",
            "regex": "firebase[_-]?api[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "firebase_key",
            "regex": "firebase[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "firebase_project_develop",
            "regex": "firebase[_-]?project[_-]?develop(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "firebase_token",
            "regex": "firebase[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "firefox_secret",
            "regex": "firefox[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "flask_secret_key",
            "regex": "flask[_-]?secret[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "flickr_api_key",
            "regex": "flickr[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "flickr_api_secret",
            "regex": "flickr[_-]?api[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "fossa_api_key",
            "regex": "fossa[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ftp_host",
            "regex": "ftp[_-]?host(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ftp_login",
            "regex": "ftp[_-]?login(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ftp_password",
            "regex": "ftp[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ftp_pw",
            "regex": "ftp[_-]?pw(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ftp_user",
            "regex": "ftp[_-]?user(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ftp_username",
            "regex": "ftp[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gcloud_bucket",
            "regex": "gcloud[_-]?bucket(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gcloud_project",
            "regex": "gcloud[_-]?project(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gcloud_service_key",
            "regex": "gcloud[_-]?service[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gcp_api_key",
            "regex": "(AIza[0-9A-Za-z-_]{35})",
            "severity": "5"
        },
        {
            "title": "gcr_password",
            "regex": "gcr[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gcs_bucket",
            "regex": "gcs[_-]?bucket(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gh_api_key",
            "regex": "gh[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gh_email",
            "regex": "gh[_-]?email(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gh_next_oauth_client_secret",
            "regex": "gh[_-]?next[_-]?oauth[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gh_next_unstable_oauth_client_id",
            "regex": "gh[_-]?next[_-]?unstable[_-]?oauth[_-]?client[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gh_next_unstable_oauth_client_secret",
            "regex": "gh[_-]?next[_-]?unstable[_-]?oauth[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gh_oauth_client_secret",
            "regex": "gh[_-]?oauth[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gh_oauth_token",
            "regex": "gh[_-]?oauth[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gh_repo_token",
            "regex": "gh[_-]?repo[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gh_token",
            "regex": "gh[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gh_unstable_oauth_client_secret",
            "regex": "gh[_-]?unstable[_-]?oauth[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ghb_token",
            "regex": "ghb[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ghost_api_key",
            "regex": "ghost[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "git_author_email",
            "regex": "git[_-]?author[_-]?email(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "git_author_name",
            "regex": "git[_-]?author[_-]?name(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "git_committer_email",
            "regex": "git[_-]?committer[_-]?email(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "git_committer_name",
            "regex": "git[_-]?committer[_-]?name(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "git_email",
            "regex": "git[_-]?email(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "git_name",
            "regex": "git[_-]?name(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "git_token",
            "regex": "git[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github",
            "regex": "(github(.{0,20})?(?-i)['\"][0-9a-zA-Z]{35,40}['\"])",
            "severity": "5"
        },
        {
            "title": "github_access_token",
            "regex": "github[_-]?access[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_access_token",
            "regex": "[a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github.com*",
            "severity": "5"
        },
        {
            "title": "github_api_key",
            "regex": "github[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_api_token",
            "regex": "github[_-]?api[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_auth",
            "regex": "github[_-]?auth(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_auth_token",
            "regex": "github[_-]?auth[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_client_secret",
            "regex": "github[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_deploy_hb_doc_pass",
            "regex": "github[_-]?deploy[_-]?hb[_-]?doc[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_deployment_token",
            "regex": "github[_-]?deployment[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_hunter_token",
            "regex": "github[_-]?hunter[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_hunter_username",
            "regex": "github[_-]?hunter[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_key",
            "regex": "github[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_oauth",
            "regex": "github[_-]?oauth(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_oauth_token",
            "regex": "github[_-]?oauth[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_password",
            "regex": "github[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_pwd",
            "regex": "github[_-]?pwd(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_release_token",
            "regex": "github[_-]?release[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_repo",
            "regex": "github[_-]?repo(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_token",
            "regex": "github[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "github_tokens",
            "regex": "github[_-]?tokens(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gitlab_user_email",
            "regex": "gitlab[_-]?user[_-]?email(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gogs_password",
            "regex": "gogs[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "google_account_type",
            "regex": "google[_-]?account[_-]?type(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "google_captcha",
            "regex": "(6L[0-9A-Za-z-_]{38})",
            "severity": "5"
        },
        {
            "title": "google_client_email",
            "regex": "google[_-]?client[_-]?email(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "google_client_id",
            "regex": "google[_-]?client[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "google_client_secret",
            "regex": "google[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "google_maps_api_key",
            "regex": "google[_-]?maps[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "google_oauth",
            "regex": "(ya29.[0-9A-Za-z-_]+)",
            "severity": "5"
        },
        {
            "title": "google_patterns",
            "regex": "(?i)(?:google_client_id|google_client_secret|google_client_token)",
            "severity": "5"
        },
        {
            "title": "google_private_key",
            "regex": "google[_-]?private[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "google_url",
            "regex": "([0-9]{12}-[a-z0-9]{32}.apps.googleusercontent.com)",
            "severity": "5"
        },
        {
            "title": "gpg_key_name",
            "regex": "gpg[_-]?key[_-]?name(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gpg_keyname",
            "regex": "gpg[_-]?keyname(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gpg_ownertrust",
            "regex": "gpg[_-]?ownertrust(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gpg_passphrase",
            "regex": "gpg[_-]?passphrase(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gpg_private_key",
            "regex": "gpg[_-]?private[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gpg_secret_keys",
            "regex": "gpg[_-]?secret[_-]?keys(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gradle_publish_key",
            "regex": "gradle[_-]?publish[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gradle_publish_secret",
            "regex": "gradle[_-]?publish[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gradle_signing_key_id",
            "regex": "gradle[_-]?signing[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gradle_signing_password",
            "regex": "gradle[_-]?signing[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "gren_github_token",
            "regex": "gren[_-]?github[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "grgit_user",
            "regex": "grgit[_-]?user(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "hab_auth_token",
            "regex": "hab[_-]?auth[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "hab_key",
            "regex": "hab[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "hb_codesign_gpg_pass",
            "regex": "hb[_-]?codesign[_-]?gpg[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "hb_codesign_key_pass",
            "regex": "hb[_-]?codesign[_-]?key[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "heroku_api_key",
            "regex": "heroku[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "heroku_api_key_api_key",
            "regex": "([h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})",
            "severity": "5"
        },
        {
            "title": "heroku_email",
            "regex": "heroku[_-]?email(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "heroku_token",
            "regex": "heroku[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "hockeyapp",
            "regex": "hockey.{0,50}(\"|')?[0-9a-f]{32}(\"|')?",
            "severity": "5"
        },
        {
            "title": "hockeyapp_token",
            "regex": "hockeyapp[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "homebrew_github_api_token",
            "regex": "homebrew[_-]?github[_-]?api[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "hub_dxia2_password",
            "regex": "hub[_-]?dxia2[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ij_repo_password",
            "regex": "ij[_-]?repo[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ij_repo_username",
            "regex": "ij[_-]?repo[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "index_name",
            "regex": "index[_-]?name(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "integration_test_api_key",
            "regex": "integration[_-]?test[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "integration_test_appid",
            "regex": "integration[_-]?test[_-]?appid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "internal_secrets",
            "regex": "internal[_-]?secrets(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ios_docs_deploy_token",
            "regex": "ios[_-]?docs[_-]?deploy[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "itest_gh_token",
            "regex": "itest[_-]?gh[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "jdbc",
            "regex": "mysql: jdbc:mysql(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "jdbc_databaseurl",
            "regex": "jdbc[_-]?databaseurl(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "jdbc_host",
            "regex": "jdbc[_-]?host(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "json_web1_token",
            "regex": "(eyJ[a-zA-Z0-9-]{10,}.eyJ[a-zA-Z0-9-]{10,}.[a-zA-Z0-9-]{10,})",
            "severity": "5"
        },
        {
            "title": "jwt_secret",
            "regex": "jwt[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "kafka_admin_url",
            "regex": "kafka[_-]?admin[_-]?url(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "kafka_instance_name",
            "regex": "kafka[_-]?instance[_-]?name(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "kafka_rest_url",
            "regex": "kafka[_-]?rest[_-]?url(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "keystore_pass",
            "regex": "keystore[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "kovan_private_key",
            "regex": "kovan[_-]?private[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "kubecfg_s3_path",
            "regex": "kubecfg[_-]?s3[_-]?path(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "kubeconfig",
            "regex": "kubeconfig(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "kxoltsn3vogdop92m",
            "regex": "kxoltsn3vogdop92m(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "leanplum_key",
            "regex": "leanplum[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "lektor_deploy_password",
            "regex": "lektor[_-]?deploy[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "lektor_deploy_username",
            "regex": "lektor[_-]?deploy[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "lighthouse_api_key",
            "regex": "lighthouse[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "linkedin_client_id",
            "regex": "(linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"])",
            "severity": "5"
        },
        {
            "title": "linkedin_client_secretor lottie_s3_api_key",
            "regex": "linkedin[_-]?client[_-]?secretor lottie[_-]?s3[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "linkedin_secret_key",
            "regex": "(linkedin(.{0,20})?['\"][0-9a-z]{16}['\"])",
            "severity": "5"
        },
        {
            "title": "linux_signing_key",
            "regex": "linux[_-]?signing[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ll_publish_url",
            "regex": "ll[_-]?publish[_-]?url(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ll_shared_key",
            "regex": "ll[_-]?shared[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "looker_test_runner_client_secret",
            "regex": "looker[_-]?test[_-]?runner[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "lottie_happo_api_key",
            "regex": "lottie[_-]?happo[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "lottie_happo_secret_key",
            "regex": "lottie[_-]?happo[_-]?secret[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "lottie_s3_secret_key",
            "regex": "lottie[_-]?s3[_-]?secret[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "lottie_upload_cert_key_password",
            "regex": "lottie[_-]?upload[_-]?cert[_-]?key[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "lottie_upload_cert_key_store_password",
            "regex": "lottie[_-]?upload[_-]?cert[_-]?key[_-]?store[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "magento_auth_password",
            "regex": "magento[_-]?auth[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "magento_auth_username",
            "regex": "magento[_-]?auth[_-]?username (=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "magento_password",
            "regex": "magento[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mail_password",
            "regex": "mail[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mailchimp",
            "regex": "(W(?:[a-f0-9]{32}(-us[0-9]{1,2}))a-zA-Z0-9)",
            "severity": "5"
        },
        {
            "title": "mailchimp_api_key",
            "regex": "mailchimp[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mailchimp_key",
            "regex": "mailchimp[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mailer_password",
            "regex": "mailer[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mailgun",
            "regex": "(key-[0-9a-f]{32})",
            "severity": "5"
        },
        {
            "title": "mailgun_api_key",
            "regex": "key-[0-9a-zA-Z]{32}",
            "severity": "5"
        },
        {
            "title": "mailgun_api_key",
            "regex": "mailgun[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mailgun_apikey",
            "regex": "mailgun[_-]?apikey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mailgun_password",
            "regex": "mailgun[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mailgun_priv_key",
            "regex": "mailgun[_-]?priv[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mailgun_pub_apikey",
            "regex": "mailgun[_-]?pub[_-]?apikey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mailgun_pub_key",
            "regex": "mailgun[_-]?pub[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mailgun_secret_api_key",
            "regex": "mailgun[_-]?secret[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "manage_key",
            "regex": "manage[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "manage_secret",
            "regex": "manage[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "management_token",
            "regex": "management[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "managementapiaccesstoken",
            "regex": "managementapiaccesstoken(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mandrill_api_key",
            "regex": "mandrill[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "manifest_app_token",
            "regex": "manifest[_-]?app[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "manifest_app_url",
            "regex": "manifest[_-]?app[_-]?url(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mapbox_access_token",
            "regex": "mapbox[_-]?access[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mapbox_api_token",
            "regex": "mapbox[_-]?api[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mapbox_aws_access_key_id",
            "regex": "mapbox[_-]?aws[_-]?access[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mapbox_aws_secret_access_key",
            "regex": "mapbox[_-]?aws[_-]?secret[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mapboxaccesstoken",
            "regex": "mapboxaccesstoken(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mg_api_key",
            "regex": "mg[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mg_public_api_key",
            "regex": "mg[_-]?public[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mh_apikey",
            "regex": "mh[_-]?apikey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mh_password",
            "regex": "mh[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mile_zero_key",
            "regex": "mile[_-]?zero[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "minio_access_key",
            "regex": "minio[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "minio_secret_key",
            "regex": "minio[_-]?secret[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "multi_bob_sid",
            "regex": "multi[_-]?bob[_-]?sid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "multi_connect_sid",
            "regex": "multi[_-]?connect[_-]?sid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "multi_disconnect_sid",
            "regex": "multi[_-]?disconnect[_-]?sid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "multi_workflow_sid",
            "regex": "multi[_-]?workflow[_-]?sid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "multi_workspace_sid",
            "regex": "multi[_-]?workspace[_-]?sid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "my_secret_env",
            "regex": "my[_-]?secret[_-]?env(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mysql_database",
            "regex": "mysql[_-]?database(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mysql_hostname",
            "regex": "mysql[_-]?hostname(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mysql_password",
            "regex": "mysql[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mysql_root_password",
            "regex": "mysql[_-]?root[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mysql_user",
            "regex": "mysql[_-]?user(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mysql_username",
            "regex": "mysql[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mysqlmasteruser",
            "regex": "mysqlmasteruser(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "mysqlsecret",
            "regex": "mysqlsecret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "nativeevents",
            "regex": "nativeevents(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "netlify_api_key",
            "regex": "netlify[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "new_relic_beta_token",
            "regex": "new[_-]?relic[_-]?beta[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "nexus_password",
            "regex": "nexus[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "nexuspassword",
            "regex": "nexuspassword(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ngrok_auth_token",
            "regex": "ngrok[_-]?auth[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ngrok_token",
            "regex": "ngrok[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "node_env",
            "regex": "node[_-]?env(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "node_pre_gyp_accesskeyid",
            "regex": "node[_-]?pre[_-]?gyp[_-]?accesskeyid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "node_pre_gyp_github_token",
            "regex": "node[_-]?pre[_-]?gyp[_-]?github[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "node_pre_gyp_secretaccesskey",
            "regex": "node[_-]?pre[_-]?gyp[_-]?secretaccesskey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "non_token",
            "regex": "non[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "now_token",
            "regex": "now[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "npm_api_key",
            "regex": "npm[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "npm_api_token",
            "regex": "npm[_-]?api[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "npm_auth_token",
            "regex": "npm[_-]?auth[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "npm_email",
            "regex": "npm[_-]?email(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "npm_password",
            "regex": "npm[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "npm_secret_key",
            "regex": "npm[_-]?secret[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "npm_token",
            "regex": "npm[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "npm_token",
            "regex": "([a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12})",
            "severity": "5"
        },
        {
            "title": "nuget_api_key",
            "regex": "(oy2[a-z0-9]{43})",
            "severity": "5"
        },
        {
            "title": "nuget_api_key",
            "regex": "nuget[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "nuget_apikey",
            "regex": "nuget[_-]?apikey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "nuget_key",
            "regex": "nuget[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "numbers_service_pass",
            "regex": "numbers[_-]?service[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "oauth_token",
            "regex": "oauth[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "object_storage_password",
            "regex": "object[_-]?storage[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "object_storage_region_name",
            "regex": "object[_-]?storage[_-]?region[_-]?name(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "object_store_bucket",
            "regex": "object[_-]?store[_-]?bucket(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "object_store_creds",
            "regex": "object[_-]?store[_-]?creds(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "oc_pass",
            "regex": "oc[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "octest_app_password",
            "regex": "octest[_-]?app[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "octest_app_username",
            "regex": "octest[_-]?app[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "octest_password",
            "regex": "octest[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ofta_key",
            "regex": "ofta[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ofta_region",
            "regex": "ofta[_-]?region(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ofta_secret",
            "regex": "ofta[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "okta_client_token",
            "regex": "okta[_-]?client[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "okta_oauth2_client_secret",
            "regex": "okta[_-]?oauth2[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "okta_oauth2_clientsecret",
            "regex": "okta[_-]?oauth2[_-]?clientsecret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "omise_key",
            "regex": "omise[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "omise_pkey",
            "regex": "omise[_-]?pkey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "omise_pubkey",
            "regex": "omise[_-]?pubkey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "omise_skey",
            "regex": "omise[_-]?skey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "onesignal_api_key",
            "regex": "onesignal[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "onesignal_user_auth_key",
            "regex": "onesignal[_-]?user[_-]?auth[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "open_whisk_key",
            "regex": "open[_-]?whisk[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "openwhisk_key",
            "regex": "openwhisk[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "org_gradle_project_sonatype_nexus_password",
            "regex": "org[_-]?gradle[_-]?project[_-]?sonatype[_-]?nexus[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "org_project_gradle_sonatype_nexus_password",
            "regex": "org[_-]?project[_-]?gradle[_-]?sonatype[_-]?nexus[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "os_auth_url",
            "regex": "os[_-]?auth[_-]?url(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "os_password",
            "regex": "os[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ossrh_jira_password",
            "regex": "ossrh[_-]?jira[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ossrh_pass",
            "regex": "ossrh[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ossrh_password",
            "regex": "ossrh[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ossrh_secret",
            "regex": "ossrh[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ossrh_username",
            "regex": "ossrh[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "outlook_team",
            "regex": "(https://outlook.office.com/webhook/[0-9a-f-]{36}@)",
            "severity": "5"
        },
        {
            "title": "packagecloud_token",
            "regex": "packagecloud[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "pagerduty_apikey",
            "regex": "pagerduty[_-]?apikey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "parse_js_key",
            "regex": "parse[_-]?js[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "passwordtravis",
            "regex": "passwordtravis(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "paypal",
            "regex": "[a-zA-Z0-9]{1,2}([E][A-Z]{1}[a-zA-Z0-9_-]{78})[a-zA-Z0-9]{1,2}$",
            "severity": "5"
        },
        {
            "title": "paypal_braintree_access_token",
            "regex": "(access_token$production$[0-9a-z]{16}$[0-9a-f]{32})",
            "severity": "5"
        },
        {
            "title": "paypal_client_secret",
            "regex": "paypal[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "percy_project",
            "regex": "percy[_-]?project(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "percy_token",
            "regex": "percy[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "personal_key",
            "regex": "personal[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "personal_secret",
            "regex": "personal[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "pg_database",
            "regex": "pg[_-]?database(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "pg_host",
            "regex": "pg[_-]?host(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "places_api_key",
            "regex": "places[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "places_apikey",
            "regex": "places[_-]?apikey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "plotly_apikey",
            "regex": "plotly[_-]?apikey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "plugin_password",
            "regex": "plugin[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "postgres_env_postgres_db",
            "regex": "postgres[_-]?env[_-]?postgres[_-]?db(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "postgres_env_postgres_password",
            "regex": "postgres[_-]?env[_-]?postgres[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "postgresql_db",
            "regex": "postgresql[_-]?db(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "postgresql_pass",
            "regex": "postgresql[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "prebuild_auth",
            "regex": "prebuild[_-]?auth(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "preferred_username",
            "regex": "preferred[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "pring_mail_username",
            "regex": "pring[_-]?mail[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "private_key",
            "regex": "(?i)-----(?:(?:BEGIN|END) )(?:(?:EC|PGP|DSA|RSA|OPENSSH).)?PRIVATE.KEY(.BLOCK)?-----",
            "severity": "5"
        },
        {
            "title": "private_signing_password",
            "regex": "private[_-]?signing[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "prod_access_key_id",
            "regex": "prod[_-]?access[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "prod_password",
            "regex": "prod[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "prod_secret_key",
            "regex": "prod[_-]?secret[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "project_config",
            "regex": "project[_-]?config(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "publish_access",
            "regex": "publish[_-]?access(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "publish_key",
            "regex": "publish[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "publish_secret",
            "regex": "publish[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "pushover_token",
            "regex": "pushover[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "pypi_passowrd",
            "regex": "pypi[_-]?passowrd(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "qiita_token",
            "regex": "qiita[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "quip_token",
            "regex": "quip[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "rabbitmq_password",
            "regex": "rabbitmq[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "randrmusicapiaccesstoken",
            "regex": "randrmusicapiaccesstoken(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "redis_stunnel_urls",
            "regex": "redis[_-]?stunnel[_-]?urls(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "rediscloud_url",
            "regex": "rediscloud[_-]?url(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "refresh_token",
            "regex": "refresh[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "registry_pass",
            "regex": "registry[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "registry_secure",
            "regex": "registry[_-]?secure(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "release_gh_token",
            "regex": "release[_-]?gh[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "release_token",
            "regex": "release[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "reporting_webdav_pwd",
            "regex": "reporting[_-]?webdav[_-]?pwd(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "reporting_webdav_url",
            "regex": "reporting[_-]?webdav[_-]?url(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "repotoken",
            "regex": "repotoken(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "rest_api_key",
            "regex": "rest[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "rinkeby_private_key",
            "regex": "rinkeby[_-]?private[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ropsten_private_key",
            "regex": "ropsten[_-]?private[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "route53_access_key_id",
            "regex": "route53[_-]?access[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "rtd_key_pass",
            "regex": "rtd[_-]?key[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "rtd_store_pass",
            "regex": "rtd[_-]?store[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "rubygems_auth_token",
            "regex": "rubygems[_-]?auth[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "s3_access_key",
            "regex": "s3[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "s3_access_key_id",
            "regex": "s3[_-]?access[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "s3_bucket_name_app_logs",
            "regex": "s3[_-]?bucket[_-]?name[_-]?app[_-]?logs(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "s3_bucket_name_assets",
            "regex": "s3[_-]?bucket[_-]?name[_-]?assets(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "s3_external_3_amazonaws_com",
            "regex": "s3[_-]?external[_-]?3[_-]?amazonaws[_-]?com(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "s3_key",
            "regex": "s3[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "s3_key_app_logs",
            "regex": "s3[_-]?key[_-]?app[_-]?logs(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "s3_key_assets",
            "regex": "s3[_-]?key[_-]?assets(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "s3_secret_app_logs",
            "regex": "s3[_-]?secret[_-]?app[_-]?logs(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "s3_secret_assets",
            "regex": "s3[_-]?secret[_-]?assets(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "s3_secret_key",
            "regex": "s3[_-]?secret[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "s3_user_secret",
            "regex": "s3[_-]?user[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sacloud_access_token",
            "regex": "sacloud[_-]?access[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sacloud_access_token_secret",
            "regex": "sacloud[_-]?access[_-]?token[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sacloud_api",
            "regex": "sacloud[_-]?api(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "salesforce_bulk_test_password",
            "regex": "salesforce[_-]?bulk[_-]?test[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "salesforce_bulk_test_security_token",
            "regex": "salesforce[_-]?bulk[_-]?test[_-]?security[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sandbox_access_token",
            "regex": "sandbox[_-]?access[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sandbox_aws_access_key_id",
            "regex": "sandbox[_-]?aws[_-]?access[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sandbox_aws_secret_access_key",
            "regex": "sandbox[_-]?aws[_-]?secret[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sauce_access_key",
            "regex": "sauce[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sauce_token",
            "regex": "(sauce.{0,50}(\"|')?[0-9a-f-]{36}(\"|')?)",
            "severity": "5"
        },
        {
            "title": "scrutinizer_token",
            "regex": "scrutinizer[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sdr_token",
            "regex": "sdr[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secret_0",
            "regex": "secret[_-]?0(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secret_1",
            "regex": "secret[_-]?1(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secret_10",
            "regex": "secret[_-]?10(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secret_11",
            "regex": "secret[_-]?11(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secret_2",
            "regex": "secret[_-]?2(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secret_3",
            "regex": "secret[_-]?3(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secret_4",
            "regex": "secret[_-]?4(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secret_5",
            "regex": "secret[_-]?5(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secret_6",
            "regex": "secret[_-]?6(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secret_7",
            "regex": "secret[_-]?7(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secret_8",
            "regex": "secret[_-]?8(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secret_9",
            "regex": "secret[_-]?9(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secret_key_base",
            "regex": "secret[_-]?key[_-]?base(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secretaccesskey",
            "regex": "secretaccesskey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "secretkey",
            "regex": "secretkey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "segment_api_key",
            "regex": "segment[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "selion_log_level_dev",
            "regex": "selion[_-]?log[_-]?level[_-]?dev(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "selion_selenium_host",
            "regex": "selion[_-]?selenium[_-]?host(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sendgrid",
            "regex": "sendgrid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sendgrid_api_key",
            "regex": "sendgrid[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sendgrid_api_key",
            "regex": "(SG.[a-zA-Z0-9-]{16,32}.[a-zA-Z0-9-]{16,64})",
            "severity": "5"
        },
        {
            "title": "sendgrid_key",
            "regex": "sendgrid[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sendgrid_password",
            "regex": "sendgrid[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sendgrid_user",
            "regex": "sendgrid[_-]?user(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sendgrid_username",
            "regex": "sendgrid[_-]?username(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sendwithus_key",
            "regex": "sendwithus[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sentry_auth_token",
            "regex": "sentry[_-]?auth[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sentry_default_org",
            "regex": "sentry[_-]?default[_-]?org(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sentry_endpoint",
            "regex": "sentry[_-]?endpoint(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sentry_key",
            "regex": "sentry[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "service_account_secret",
            "regex": "service[_-]?account[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ses_access_key",
            "regex": "ses[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ses_secret_key",
            "regex": "ses[_-]?secret[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "setdstaccesskey",
            "regex": "setdstaccesskey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "setdstsecretkey",
            "regex": "setdstsecretkey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "setsecretkey",
            "regex": "setsecretkey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "signing_key",
            "regex": "signing[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "signing_key_password",
            "regex": "signing[_-]?key[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "signing_key_secret",
            "regex": "signing[_-]?key[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "signing_key_sid",
            "regex": "signing[_-]?key[_-]?sid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "slack_api_token",
            "regex": "(xox[aboprs]-([0-9a-zA-Z-]{8,})?)",
            "severity": "5"
        },
        {
            "title": "slack_webhook_url",
            "regex": "(hooks.slack.com\/services\/T[A-Z0-9]{8}\/B[A-Z0-9]{8}\/[a-zA-Z0-9]{1,})",
            "severity": "5"
        },
        {
            "title": "slash_developer_space",
            "regex": "slash[_-]?developer[_-]?space(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "slash_developer_space_key",
            "regex": "slash[_-]?developer[_-]?space[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "slate_user_email",
            "regex": "slate[_-]?user[_-]?email(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "snoowrap_client_secret",
            "regex": "snoowrap[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "snoowrap_password",
            "regex": "snoowrap[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "snoowrap_refresh_token",
            "regex": "snoowrap[_-]?refresh[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "snyk_api_token",
            "regex": "snyk[_-]?api[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "snyk_token",
            "regex": "snyk[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "socrata_app_token",
            "regex": "socrata[_-]?app[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "socrata_password",
            "regex": "socrata[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sonar_organization_key",
            "regex": "sonar[_-]?organization[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sonar_project_key",
            "regex": "sonar[_-]?project[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sonar_token",
            "regex": "sonar[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sonarqube_docs_api_key",
            "regex": "(sonar.{0,50}(\"|')?[0-9a-f]{40}(\"|')?)",
            "severity": "5"
        },
        {
            "title": "sonatype_gpg_key_name",
            "regex": "sonatype[_-]?gpg[_-]?key[_-]?name(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sonatype_gpg_passphrase",
            "regex": "sonatype[_-]?gpg[_-]?passphrase(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sonatype_nexus_password",
            "regex": "sonatype[_-]?nexus[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sonatype_pass",
            "regex": "sonatype[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sonatype_password",
            "regex": "sonatype[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sonatype_token_password",
            "regex": "sonatype[_-]?token[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sonatype_token_user",
            "regex": "sonatype[_-]?token[_-]?user(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sonatypepassword",
            "regex": "sonatypepassword(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "soundcloud_client_secret",
            "regex": "soundcloud[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "soundcloud_password",
            "regex": "soundcloud[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "spaces_access_key_id",
            "regex": "spaces[_-]?access[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "spaces_secret_access_key",
            "regex": "spaces[_-]?secret[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "spotify_api_access_token",
            "regex": "spotify[_-]?api[_-]?access[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "spotify_api_client_secret",
            "regex": "spotify[_-]?api[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "spring_mail_password",
            "regex": "spring[_-]?mail[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sqsaccesskey",
            "regex": "sqsaccesskey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "sqssecretkey",
            "regex": "sqssecretkey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "square_app_secret",
            "regex": "(sq0[a-z]{3}-[0-9A-Za-z-_]{20,50})",
            "severity": "5"
        },
        {
            "title": "square_reader_sdk_repository_password",
            "regex": "square[_-]?reader[_-]?sdk[_-]?repository[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "srcclr_api_token",
            "regex": "srcclr[_-]?api[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ssh_password",
            "regex": "(sshpass -p.*['|\"])",
            "severity": "5"
        },
        {
            "title": "sshpass",
            "regex": "sshpass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "ssmtp_config",
            "regex": "ssmtp[_-]?config(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "staging_base_url_runscope",
            "regex": "staging[_-]?base[_-]?url[_-]?runscope(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "star_test_aws_access_key_id",
            "regex": "star[_-]?test[_-]?aws[_-]?access[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "star_test_bucket",
            "regex": "star[_-]?test[_-]?bucket(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "star_test_location",
            "regex": "star[_-]?test[_-]?location(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "star_test_secret_access_key",
            "regex": "star[_-]?test[_-]?secret[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "starship_account_sid",
            "regex": "starship[_-]?account[_-]?sid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "starship_auth_token",
            "regex": "starship[_-]?auth[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "stormpath_api_key_id",
            "regex": "stormpath[_-]?api[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "stormpath_api_key_secret",
            "regex": "stormpath[_-]?api[_-]?key[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "strip_publishable_key",
            "regex": "strip[_-]?publishable[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "strip_secret_key",
            "regex": "strip[_-]?secret[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "stripe_private",
            "regex": "stripe[_-]?private(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "stripe_public",
            "regex": "stripe[_-]?public(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "stripe_restricted_api",
            "regex": "(rk_live_[0-9a-zA-Z]{24,34})",
            "severity": "5"
        },
        {
            "title": "stripe_standard_api",
            "regex": "(sk_live_[0-9a-zA-Z]{24,34})",
            "severity": "5"
        },
        {
            "title": "surge_login",
            "regex": "surge[_-]?login(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "surge_token",
            "regex": "surge[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "svn_pass",
            "regex": "svn[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "tesco_api_key",
            "regex": "tesco[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "test_github_token",
            "regex": "test[_-]?github[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "test_test",
            "regex": "test[_-]?test(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "tester_keys_password",
            "regex": "tester[_-]?keys[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "thera_oss_access_key",
            "regex": "thera[_-]?oss[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "token_core_java",
            "regex": "token[_-]?core[_-]?java(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "travis_access_token",
            "regex": "travis[_-]?access[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "travis_api_token",
            "regex": "travis[_-]?api[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "travis_branch",
            "regex": "travis[_-]?branch(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "travis_com_token",
            "regex": "travis[_-]?com[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "travis_e2e_token",
            "regex": "travis[_-]?e2e[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "travis_gh_token",
            "regex": "travis[_-]?gh[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "travis_pull_request",
            "regex": "travis[_-]?pull[_-]?request(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "travis_secure_env_vars",
            "regex": "travis[_-]?secure[_-]?env[_-]?vars(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "travis_token",
            "regex": "travis[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "trex_client_token",
            "regex": "trex[_-]?client[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "trex_okta_client_token",
            "regex": "trex[_-]?okta[_-]?client[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "twilio_api_key",
            "regex": "twilio[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "twilio_api_secret",
            "regex": "twilio[_-]?api[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "twilio_chat_account_api_service",
            "regex": "twilio[_-]?chat[_-]?account[_-]?api[_-]?service(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "twilio_configuration_sid",
            "regex": "twilio[_-]?configuration[_-]?sid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "twilio_sid",
            "regex": "twilio[_-]?sid(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "twilio_token",
            "regex": "twilio[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "twine_password",
            "regex": "twine[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "twitter",
            "regex": "([a-zA-Z0-9]{1,2}([a-zA-Z0-9]{50})[a-zA-Z0-9]{1,2}$)",
            "severity": "5"
        },
        {
            "title": "twitter_client_id",
            "regex": "(twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"])",
            "severity": "5"
        },
        {
            "title": "twitter_consumer_key",
            "regex": "twitter[_-]?consumer[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "twitter_consumer_secret",
            "regex": "twitter[_-]?consumer[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "twitter_secret_key",
            "regex": "twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"]",
            "severity": "5"
        },
        {
            "title": "twitteroauthaccesssecret",
            "regex": "twitteroauthaccesssecret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "twitteroauthaccesstoken",
            "regex": "twitteroauthaccesstoken(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "unity_password",
            "regex": "unity[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "unity_serial",
            "regex": "unity[_-]?serial(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "urban_key",
            "regex": "urban[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "urban_master_secret",
            "regex": "urban[_-]?master[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "urban_secret",
            "regex": "urban[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "us_east_1_elb_amazonaws_com",
            "regex": "us[_-]?east[_-]?1[_-]?elb[_-]?amazonaws[_-]?com(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "use_ssh",
            "regex": "use[_-]?ssh(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "user_assets_access_key_id",
            "regex": "user[_-]?assets[_-]?access[_-]?key[_-]?id(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "user_assets_secret_access_key",
            "regex": "user[_-]?assets[_-]?secret[_-]?access[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "usertravis",
            "regex": "usertravis(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "v_sfdc_client_secret",
            "regex": "v[_-]?sfdc[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "v_sfdc_password",
            "regex": "v[_-]?sfdc[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "vip_github_build_repo_deploy_key",
            "regex": "vip[_-]?github[_-]?build[_-]?repo[_-]?deploy[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "vip_github_deploy_key",
            "regex": "vip[_-]?github[_-]?deploy[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "vip_github_deploy_key_pass",
            "regex": "vip[_-]?github[_-]?deploy[_-]?key[_-]?pass(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "virustotal_apikey",
            "regex": "virustotal[_-]?apikey(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "visual_recognition_api_key",
            "regex": "visual[_-]?recognition[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "vscetoken",
            "regex": "vscetoken(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "wakatime_api_key",
            "regex": "wakatime[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "watson_conversation_password",
            "regex": "watson[_-]?conversation[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "watson_device_password",
            "regex": "watson[_-]?device[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "watson_password",
            "regex": "watson[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "widget_basic_password",
            "regex": "widget[_-]?basic[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "widget_basic_password_2",
            "regex": "widget[_-]?basic[_-]?password[_-]?2(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "widget_basic_password_3",
            "regex": "widget[_-]?basic[_-]?password[_-]?3(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "widget_basic_password_4",
            "regex": "widget[_-]?basic[_-]?password[_-]?4(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "widget_basic_password_5",
            "regex": "widget[_-]?basic[_-]?password[_-]?5(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "widget_fb_password",
            "regex": "widget[_-]?fb[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "widget_fb_password_2",
            "regex": "widget[_-]?fb[_-]?password[_-]?2(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "widget_fb_password_3",
            "regex": "widget[_-]?fb[_-]?password[_-]?3(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "widget_test_server",
            "regex": "widget[_-]?test[_-]?server(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "wincert_password",
            "regex": "wincert[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "wordpress_db_password",
            "regex": "wordpress[_-]?db[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "wordpress_db_user",
            "regex": "wordpress[_-]?db[_-]?user(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "wpjm_phpunit_google_geocode_api_key",
            "regex": "wpjm[_-]?phpunit[_-]?google[_-]?geocode[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "wporg_password",
            "regex": "wporg[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "wpt_db_password",
            "regex": "wpt[_-]?db[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "wpt_db_user",
            "regex": "wpt[_-]?db[_-]?user(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "wpt_prepare_dir",
            "regex": "wpt[_-]?prepare[_-]?dir(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "wpt_report_api_key",
            "regex": "wpt[_-]?report[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "wpt_ssh_connect",
            "regex": "wpt[_-]?ssh[_-]?connect(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "wpt_ssh_private_key_base64",
            "regex": "wpt[_-]?ssh[_-]?private[_-]?key[_-]?base64(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "www_googleapis_com",
            "regex": "www[_-]?googleapis[_-]?com(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "yangshun_gh_password",
            "regex": "yangshun[_-]?gh[_-]?password(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "yangshun_gh_token",
            "regex": "yangshun[_-]?gh[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "yt_account_client_secret",
            "regex": "yt[_-]?account[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "yt_account_refresh_token",
            "regex": "yt[_-]?account[_-]?refresh[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "yt_api_key",
            "regex": "yt[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "yt_client_secret",
            "regex": "yt[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "yt_partner_client_secret",
            "regex": "yt[_-]?partner[_-]?client[_-]?secret(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "yt_partner_refresh_token",
            "regex": "yt[_-]?partner[_-]?refresh[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "yt_server_api_key",
            "regex": "yt[_-]?server[_-]?api[_-]?key(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "zendesk_travis_github",
            "regex": "zendesk[_-]?travis[_-]?github(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "zensonatypepassword",
            "regex": "zensonatypepassword(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "zhuliang_gh_token",
            "regex": "zhuliang[_-]?gh[_-]?token(=| =|:| :)",
            "severity": "5"
        },
        {
            "title": "zopim_account_key",
            "regex": "zopim[_-]?account[_-]?key(=| =|:| :)",
            "severity": "5"
        }
    ]
}
`)
