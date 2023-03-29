package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sync"
)

type Token struct {
	Name    string
	Pattern *regexp.Regexp
}

func fetchURL(url string, tokens []*Token, resultMap *sync.Map) {
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	bodyString := string(bodyBytes)

	matchesMap := make(map[string][]string)

	for _, token := range tokens {
		matches := token.Pattern.FindAllString(bodyString, -1)
		if len(matches) > 0 {
			matchesMap[token.Name] = matches
		}
	}

	if len(matchesMap) > 0 {
		resultMap.Store(url, matchesMap)
	}
}

func main() {
	
		tokens := []*Token{
	{"Twitter_Access_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z\\/+]{40})\s*['"]{0,3}$`)},
	{"Facebook_OAuth_Token", regexp.MustCompile(`^['"]{0,3}\s*(EA[A-Za-z0-9]{32})\s*['"]{0,3}$`)},
	{"Google_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(AIza[0-9A-Za-z\\-_]{35})\s*['"]{0,3}$`)},
	{"AWS_Access_Key_ID", regexp.MustCompile(`^['"]{0,3}\s*(AKIA[0-9A-Z]{16})\s*['"]{0,3}$`)},
	{"AWS_Secret_Access_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z\\/+]{40})\s*['"]{0,3}$`)},
	{"Stripe_Live_Secret_Key", regexp.MustCompile(`^['"]{0,3}\s*(sk_live_[0-9a-zA-Z]{24})\s*['"]{0,3}$`)},
	{"Stripe_Live_Publishable_Key", regexp.MustCompile(`^['"]{0,3}\s*(pk_live_[0-9a-zA-Z]{24})\s*['"]{0,3}$`)},
	{"Square_Access_Token", regexp.MustCompile(`^['"]{0,3}\s*(sq0[a-z]{3}-[0-9A-Za-z\\-_]{22,43})\s*['"]{0,3}$`)},
	{"SendGrid_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(SG\\.[0-9a-zA-Z\\-_]{22,43}\\.[0-9a-zA-Z\\-_]{22,43})\s*['"]{0,3}$`)},
	{"GitHub_OAuth_Access_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{40})\s*['"]{0,3}$`)},
	{"Twilio_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(SK[0-9a-fA-F]{32})\s*['"]{0,3}$`)},
	{"Twilio_Account_SID", regexp.MustCompile(`^['"]{0,3}\s*(AC[0-9a-fA-F]{32})\s*['"]{0,3}$`)},
	{"Twilio_Auth_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{32})\s*['"]{0,3}$`)},
	{"LinkedIn_OAuth_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{12}\-[0-9a-zA-Z]{4}\-[0-9a-zA-Z]{4}\-[0-9a-zA-Z]{4}\-[0-9a-zA-Z]{12})\s*['"]{0,3}$`)},
	{"Slack_API_Token", regexp.MustCompile(`^['"]{0,3}\s*(xox[p|b|o|a]\-[0-9]{12}\-[0-9]{12}\-[0-9]{12}\-[0-9a-z]{32})\s*['"]{0,3}$`)},
	{"Slack_Bot_Token", regexp.MustCompile(`^['"]{0,3}\s*(xoxb\-[0-9]{12}\-[0-9]{12}\-[0-9a-z]{24})\s*['"]{0,3}$`)},
	{"MailChimp_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-f]{32}\-us[0-9]{1,2})\s*['"]{0,3}$`)},
	{"Mailgun_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(key\-[0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Microsoft_Azure_Subscription_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{32})\s*['"]{0,3}$`)},
	{"Microsoft_Azure_Tenant_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12})\s*['"]{0,3}$`)},
	{"Microsoft_Azure_Client_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12})\s*['"]{0,3}$`)},
	{"Microsoft_Azure_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Azure_DevOps_Personal_Access_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{52})\s*['"]{0,3}$`)},
	{"PayPal_Client_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"PayPal_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Shopify_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{32})\s*['"]{0,3}$`)},
	{"Shopify_API_Password", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Spotify_API_Client_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{32})\s*['"]{0,3}$`)},
	{"Spotify_API_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{32})\s*['"]{0,3}$`)},
	{"Braintree_Merchant_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-z]{16})\s*['"]{0,3}$`)},
	{"Braintree_Public_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-z]{32})\s*['"]{0,3}$`)},
	{"Braintree_Private_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Nexmo_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{20})\s*['"]{0,3}$`)},
	{"Nexmo_API_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{8})\s*['"]{0,3}$`)},
	{"Plaid_Client_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{24})\s*['"]{0,3}$`)},
	{"Plaid_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Plaid_Public_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{30})\s*['"]{0,3}$`)},
	{"Mapbox_Access_Token", regexp.MustCompile(`^['"]{0,3}\s*(pk\\.eyJ1[0-9a-zA-Z_]{10,})\s*['"]{0,3}$`)},
	{"Algolia_Application_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9A-Z]{10})\s*['"]{0,3}$`)},
	{"Algolia_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Algolia_Admin_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Zendesk_API_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Zendesk_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"OpenAI_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"QuickBooks_Client_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"QuickBooks_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Heroku_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{40})\s*['"]{0,3}$`)},
	{"Cloudinary_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9]{15})\s*['"]{0,3}$`)},
	{"Cloudinary_API_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"IFTTT_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Zoom_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Zoom_API_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z\\+\\/]{43}=?)\s*['"]{0,3}$`)},
	{"Trello_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{32})\s*['"]{0,3}$`)},
	{"Trello_API_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{64})\s*['"]{0,3}$`)},
	{"Asana_Access_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{64})\s*['"]{0,3}$`)},
	{"Auth0_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z\\-_]{43})\s*['"]{0,3}$`)},
	{"Auth0_Management_API_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z\\-_]{64})\s*['"]{0,3}$`)},
	{"Auth0_Refresh_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z\\-_]{64})\s*['"]{0,3}$`)},
	{"Auth0_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z\\-_]{32})\s*['"]{0,3}$`)},
	{"Auth0_Client_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z\\-_]{32})\s*['"]{0,3}$`)},
	{"Auth0_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z\\-_]{43})\s*['"]{0,3}$`)},
	{"Auth0_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z\\-_]{43})\s*['"]{0,3}$`)},
	{"Firebase_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z\\-_]{28})\s*['"]{0,3}$`)},
	{"Firebase_Project_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z-_]{1,100})\s*['"]{0,3}$`)},
	{"Firebase_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z\\-_]{24})\s*['"]{0,3}$`)},
	{"Firebase_Storage_Bucket", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z-_]{1,100})\s*['"]{0,3}$`)},
	{"Firebase_Messaging_Sender_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9]{1,20})\s*['"]{0,3}$`)},
	{"Cloudflare_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-fA-F]{37})\s*['"]{0,3}$`)},
	{"DigitalOcean_API_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{64})\s*['"]{0,3}$`)},
	{"Firebase_Server_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:[a-zA-Z0-9_=-]{140,})\s*['"]{0,3}$`)},
	{"Auth0_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z-_]{32})\s*['"]{0,3}$`)},
	{"Auth0_Client_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z-_]{32})\s*['"]{0,3}$`)},
	{"Auth0_Management_API_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z-_]{32})\s*['"]{0,3}$`)},
	{"Auth0_Management_API_Client_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z-_]{32})\s*['"]{0,3}$`)},
	{"Auth0_Management_API_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z-_]{32})\s*['"]{0,3}$`)},
	{"Twilio_Flex_Account_SID", regexp.MustCompile(`^['"]{0,3}\s*(AC[a-z0-9]{32})\s*['"]{0,3}$`)},
	{"Twilio_Flex_Auth_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{32})\s*['"]{0,3}$`)},
	{"Azure_Key_Vault_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z-]{32,})\s*['"]{0,3}$`)},
	{"Zoom_API_Secret", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-zA-Z_-]{43})\s*['"]{0,3}$`)},
	{"Zoom_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-zA-Z_-]{43})\s*['"]{0,3}$`)},
	{"Stripe_Test_Secret_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:sk_test_[0-9a-zA-Z]{24})\s*['"]{0,3}$`)},
	{"Stripe_Test_Publishable_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:pk_test_[0-9a-zA-Z]{24})\s*['"]{0,3}$`)},
	{"Microsoft_Graph_API_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z-_]{48})\s*['"]{0,3}$`)},
	{"Zoom_JWT_Secret", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-zA-Z_-]{86})\s*['"]{0,3}$`)},
	{"Google_Cloud_Platform_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(AIza[0-9A-Za-z\\-_]{35})\s*['"]{0,3}$`)},
	{"Twitch_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{30})\s*['"]{0,3}$`)},
	{"Twitch_API_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{30})\s*['"]{0,3}$`)},
	{"Duo_Security_Integration_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{40})\s*['"]{0,3}$`)},
	{"Duo_Security_Secret_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{40})\s*['"]{0,3}$`)},
	{"Slack_Incoming_Webhook_URL", regexp.MustCompile(`^['"]{0,3}\s*(https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24})\s*['"]{0,3}$`)},
	{"Airtable_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(key[a-zA-Z0-9]{32})\s*['"]{0,3}$`)},
	{"DigitalOcean_API_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{64})\s*['"]{0,3}$`)},
	{"Discord_Bot_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{24}\.[0-9a-zA-Z]{6}\.[0-9a-zA-Z_-]{27})\s*['"]{0,3}$`)},
	{"Discord_Client_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z_-]{18})\s*['"]{0,3}$`)},
	{"Discord_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Mandrill_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z\\-_]{32})\s*['"]{0,3}$`)},
	{"Google_Service_Account_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:\{[\s\S]*?\})\s*['"]{0,3}$`)},
	{"Cloudflare_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{37})\s*['"]{0,3}$`)},
	{"Cloudflare_API_Email", regexp.MustCompile(`^['"]{0,3}\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*['"]{0,3}$`)},
	{"Stripe_Test_Secret_Key", regexp.MustCompile(`^['"]{0,3}\s*(sk_test_[0-9a-zA-Z]{24})\s*['"]{0,3}$`)},
	{"Stripe_Test_Publishable_Key", regexp.MustCompile(`^['"]{0,3}\s*(pk_test_[0-9a-zA-Z]{24})\s*['"]{0,3}$`)},
	{"PayPal_Sandbox_Client_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z_-]{64})\s*['"]{0,3}$`)},
	{"PayPal_Sandbox_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z_-]{64})\s*['"]{0,3}$`)},
	{"Mailgun_Public_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(pubkey-[0-9a-z]{16})\s*['"]{0,3}$`)},
	{"Mailgun_Private_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(key-[0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Sentry_DSN", regexp.MustCompile(`^['"]{0,3}\s*(https:\/\/[0-9a-z]{32}@[0-9a-z]{1,3}\.ingest\.sentry\.io\/[0-9]{1,10})\s*['"]{0,3}$`)},
	{"Elasticsearch_Password", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z_-]{20,})\s*['"]{0,3}$`)},
	{"Elasticsearch_Username", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z_-]{20,})\s*['"]{0,3}$`)},
	{"PagerDuty_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-f]{32})\s*['"]{0,3}$`)},
	{"NewRelic_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-f]{40})\s*['"]{0,3}$`)},
	{"Mixpanel_API_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-f]{32})\s*['"]{0,3}$`)},
	{"Google_Cloud_Platform_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(AIza[0-9A-Za-z\\-_]{35})\s*['"]{0,3}$`)},
	{"Google_Service_Account_Private_Key", regexp.MustCompile(`^['"]{0,3}\s*([-_a-zA-Z0-9]{42}\.p12)\s*['"]{0,3}$`)},
	{"Google_Service_Account_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*(client_secret_[0-9a-zA-Z_-]{23}\.json)\s*['"]{0,3}$`)},
	{"Auth0_API_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z_-]{43})\s*['"]{0,3}$`)},
	{"Google_Cloud_Platform_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:AIza[0-9A-Za-z\\-_]{35})\s*['"]{0,3}$`)},
	{"Microsoft_Dynamics_365_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-zA-Z+/]{44})\s*['"]{0,3}$`)},
	{"Microsoft_Dynamics_365_Client_ID", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12})\s*['"]{0,3}$`)},
	{"Microsoft_Dynamics_365_Username", regexp.MustCompile(`^['"]{0,3}\s*(?:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*['"]{0,3}$`)},
	{"Microsoft_Dynamics_365_Password", regexp.MustCompile(`^['"]{0,3}\s*(?:[^\s]+)\s*['"]{0,3}$`)},
	{"MongoDB_URI", regexp.MustCompile(`^['"]{0,3}\s*(?:mongodb(?:\\+srv)?:\/\/(?:[^:]+:[^@]+@)?[^\/?]+\.[^\/?]+\.[^\/?]+(?:$|\/|\?))\s*['"]{0,3}$`)},
	{"PayPal_BN_Code", regexp.MustCompile(`^['"]{0,3}\s*(?:\d{10,12})\s*['"]{0,3}$`)},
	{"PayPal_Billing_Agreement_ID", regexp.MustCompile(`^['"]{0,3}\s*(?:B-[\w\d]{17})\s*['"]{0,3}$`)},
	{"PayPal_Client_Metadata_ID", regexp.MustCompile(`^['"]{0,3}\s*(?:[\w-]{36,100})\s*['"]{0,3}$`)},
	{"PayPal_Invoice_ID", regexp.MustCompile(`^['"]{0,3}\s*(?:INV2-[A-Za-z0-9-_]+)\s*['"]{0,3}$`)},
	{"PayPal_Order_ID", regexp.MustCompile(`^['"]{0,3}\s*(?:\w{19,24})\s*['"]{0,3}$`)},
	{"PayPal_Payer_ID", regexp.MustCompile(`^['"]{0,3}\s*(?:[A-Z0-9]{13,30})\s*['"]{0,3}$`)},
	{"PayPal_Transaction_ID", regexp.MustCompile(`^['"]{0,3}\s*(?:[A-Z0-9]{17,30})\s*['"]{0,3}$`)},
	{"PubNub_Subscribe_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:[a-z0-9]{0,32})\s*['"]{0,3}$`)},
	{"PubNub_Publish_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:[a-z0-9]{0,32})\s*['"]{0,3}$`)},
	{"Twitch_Client_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{30})\s*['"]{0,3}$`)},
	{"Twitch_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{30})\s*['"]{0,3}$`)},
	{"PubNub_Subscribe_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z_-]{24,32})\s*['"]{0,3}$`)},
	{"PubNub_Publish_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z_-]{24,32})\s*['"]{0,3}$`)},
	{"PubNub_Secret_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z_-]{24,32})\s*['"]{0,3}$`)},
	{"PayPal_Rest_API_Client_ID", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{16,32})\s*['"]{0,3}$`)},
	{"PayPal_Rest_API_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{16,32})\s*['"]{0,3}$`)},
	{"Wistia_API_Password", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{64})\s*['"]{0,3}$`)},
	{"Wistia_API_Token", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{64})\s*['"]{0,3}$`)},
	{"Adyen_Live_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(live_[0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Adyen_Live_Merchant_Account", regexp.MustCompile(`^['"]{0,3}\s*(live_[0-9a-zA-Z]{14})\s*['"]{0,3}$`)},
	{"Klarna_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(live_[0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Klarna_API_Secret", regexp.MustCompile(`^['"]{0,3}\s*(live_[0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Klarna_API_Hosted_Account_URL", regexp.MustCompile(`^['"]{0,3}\s*(https:\/\/checkout\.(klarna\.com|klarna\.se)\/checkoutdata\/[0-9a-zA-Z_-]+)\s*['"]{0,3}$`)},
	{"Klaviyo_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(pk_[0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Klaviyo_Private_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(sk_[0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"Google_Maps_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(AIza[0-9A-Za-z\\-_]{35})\s*['"]{0,3}$`)},
	{"Google_Cloud_Platform_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-fA-F]{40})\s*['"]{0,3}$`)},
	{"Algolia_Search_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-f]{32})\s*['"]{0,3}$`)},
	{"Algolia_Admin_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-zA-Z_\\-]{32})\s*['"]{0,3}$`)},
	{"Algolia_Places_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-zA-Z_\\-]{32})\s*['"]{0,3}$`)},
	{"Auth0_Client_ID", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-zA-Z_\\-]{32})\s*['"]{0,3}$`)},
	{"Auth0_Client_Secret", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-zA-Z_\\-]{32})\s*['"]{0,3}$`)},
	{"Firebase_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-zA-Z_\\-]{24})\s*['"]{0,3}$`)},
	{"Firebase_Project_ID", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-zA-Z_\\-]{24})\s*['"]{0,3}$`)},
	{"Firebase_Messaging_Sender_ID", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9]{11,13})\s*['"]{0,3}$`)},
	{"Firebase_Service_Account_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:\{[\s\S]+\})\s*['"]{0,3}$`)},
	{"Firebase_Cloud_Messaging_Server_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-zA-Z_\\-]{24})\s*['"]{0,3}$`)},
	{"Sendinblue_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-zA-Z_\\-]{64})\s*['"]{0,3}$`)},
	{"Airtable_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:key[a-zA-Z0-9]{32})\s*['"]{0,3}$`)},
	{"Mailjet_API_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:[0-9a-zA-Z_\\-]{32})\s*['"]{0,3}$`)},
	{"MongoDB_URI", regexp.MustCompile(`^['"]{0,3}\s*(?:mongodb[+srv]{0,6}:\/\/[^\s]+)\s*['"]{0,3}$`)},
	{"Payoneer_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-fA-F]{64})\s*['"]{0,3}$`)},
	{"Zapier_API_Key", regexp.MustCompile(`^['"]{0,3}\s*([0-9a-zA-Z]{32})\s*['"]{0,3}$`)},
	{"PubNub_Secret_Key", regexp.MustCompile(`^['"]{0,3}\s*(?:[a-zA-Z0-9_-]{32})\s*['"]{0,3}$`)},
	{"api_words", regexp.MustCompile(`^['"]{0,3}\s*(api|apikey|api_key|secret|access_token|accesskey|auth_token|authkey|api-key|passwd|password|username|user)[:]*\s*['"]{0,3}$`)},
	{"platform_words", regexp.MustCompile(`^['"]{0,3}\s*(?:SK|accesskey|secretkey|aws|azure|gcp|google|facebook|github|bitbucket)_(?:[0-9a-zA-Z_-]{32,})\s*['"]{0,3}$`)},
	{"base64encoded", regexp.MustCompile(`^['"]{0,3}\s*(?:\\n|\\r|\\r\\n)[A-Za-z0-9+/=]{64}(?:\\n|\\r|\\r\\n)\s*['"]{0,3}$`)},


}
	

	scanner := bufio.NewScanner(os.Stdin)
	urls := make([]string, 0)

	for scanner.Scan() {
		url := scanner.Text()
		urls = append(urls, url)
	}

	var resultMap sync.Map
	var wg sync.WaitGroup

	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			fetchURL(url, tokens, &resultMap)
		}(url)
	}

	wg.Wait()

	resultData := make(map[string]interface{})

resultMap.Range(func(key, value interface{}) bool {
	resultData[key.(string)] = value
	return true
})

jsonData, err := json.Marshal(resultData)
if err != nil {
	fmt.Println("Error marshaling JSON:", err)
	return
}

fmt.Println(string(jsonData))

}
