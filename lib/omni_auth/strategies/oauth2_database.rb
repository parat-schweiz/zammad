class OmniAuth::Strategies::Oauth2Database < OmniAuth::Strategies::OAuth2
  option :name, 'oauth2'

  def initialize(app, *args, &block)
    # database lookup
    config = Setting.get('auth_oauth2_credentials') || {}
    args[0] = config['client_id']
    args[1] = config['client_secret']
    args[2][:client_options] = args[2][:client_options].merge(config.symbolize_keys)
    super
  end

  def callback_url
    full_host + script_name + callback_path
  end

  uid { raw_info['sub'] }

  info do
    {
      uid:        raw_info['sub'],
      login:      raw_info['sub'],
      username:   raw_info['name'],
      email:      raw_info['email'],
      first_name: raw_info['firstname'],
      last_name:  raw_info['lastname'],
    }
  end

  extra do
    {
    'raw_info' => raw_info
    }
  end

  def raw_info
    @raw_info ||= access_token.get('/api/v1/user/profile/').parsed
  end

end
