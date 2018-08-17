require 'faraday'
require 'hawk'

def get_or_fail(key, default = nil)
  result = ENV[key]
  if result.nil? && !default.nil?
    result = default
  end
  if result.nil?
    fail "Environment variable '#{key}' is required."
  end
  result
end

HOST = get_or_fail('TS_HOST', 'api.threatstack.com')
USER_ID = get_or_fail('TS_USER_ID')
ORGANIZATION_ID = get_or_fail('TS_ORGANIZATION_ID')
API_KEY = get_or_fail('TS_API_KEY')

BASE_PATH = 'https://' + HOST
URI_PATH = '/help/hawk/self-test'

credentials = {
    :id => USER_ID,
    :key => API_KEY,
    :algorithm => 'sha256'
}

req = Faraday.new(url: BASE_PATH + URI_PATH)
# We have to do this because the build_authorization_header
# doesn't return the timestamp and nonce it generates,
# so it is impossible to validate the header without generating
# those values so we can capture them
ts = Time.now.to_i
nonce = SecureRandom.hex(4)
auth_header = Hawk::Client.build_authorization_header(
    :credentials => credentials,
    :method => 'GET',
    :request_uri => URI_PATH,
    :host => HOST,
    :ext => ORGANIZATION_ID,
    :port => 443,
    :nonce => nonce,
    :ts => ts
)

req.headers['Authorization'] = auth_header

response = req.get
puts response.body.to_s

response_auth_header = response.headers['Server-Authorization']

if response_auth_header == nil
  puts "No Authentication Header is available on the response. The response failed with a #{response.status}"
elsif
  # Authenticate returns the credentials hash if the response is authentic
  auth_result = Hawk::Client.authenticate(response_auth_header, {
      :credentials => credentials,
      :method => 'GET',
      :request_uri => URI_PATH,
      :host => HOST,
      :ext => ORGANIZATION_ID,
      :payload => response.body,
      :content_type => "application/json",
      :port => 443,
      :nonce => nonce,
      :ts => ts
  })
  puts "Request Authentic: " + (auth_result['id'] == credentials['id']).to_s
end
