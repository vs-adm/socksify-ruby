#!/usr/bin/ruby

require 'test/unit'
require 'net/http'
require 'uri'

$:.unshift "#{File::dirname($0)}/../lib/"
require 'socksify'
require 'socksify/http'

class SocksifyTest < Test::Unit::TestCase
  def setup
    Socksify::debug = true
    my_ip
  end

  def disable_socks
    TCPSocket.socks_server = nil
    TCPSocket.socks_port = nil
  end
  def enable_socks
    TCPSocket.socks_server = "127.0.0.1"
    TCPSocket.socks_port = 9050
  end

  def http_tor_proxy
    Net::HTTP::SOCKSProxy("127.0.0.1", 9050)
  end

  def test_check_tor
    [['Hostname', :check_tor],
     ['IPv4', :check_tor_ip]].each do |f_name, f|
      disable_socks

      tor_direct, ip_direct = send(f)
      assert_equal(false, tor_direct)

      enable_socks

      tor_socks, ip_socks = send(f)
      assert_equal(true, tor_socks)

      assert(ip_direct != ip_socks)
    end
  end

  def test_check_tor_via_net_http
    disable_socks

     [
        ['IPv4', :check_tor_ip],
        ['Hostname', :check_tor]
     ].each do |f_name, f|
      tor_direct, ip_direct = send(f)
      assert_equal(false, tor_direct)

      tor_socks, ip_socks = send(f, http_tor_proxy)
      assert_equal(true, tor_socks)

      assert(ip_direct != ip_socks)
    end
  end

  def test_ignores
    disable_socks

    tor_direct, ip_direct = check_tor
    assert_equal(false, tor_direct)

    enable_socks
    TCPSocket.socks_ignores << 'internet.yandex.com'

    tor_socks_ignored, ip_socks_ignored = check_tor
    assert_equal(false, tor_socks_ignored)

    assert(ip_direct == ip_socks_ignored)
  end

  def get_http(http_klass, url)
    uri = URI(url)
    body = nil



    req = Net::HTTP::Get.new(uri.request_uri)
    req['Host'] = "internet.yandex.com"
    req['User-Agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.46 Safari/536.5"

    http_klass.start(uri.host, uri.port,
                     :use_ssl => uri.scheme == 'https',
                     :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|

      body = http.request(req).body
    end

    body
  end

  def check_tor(http_klass = Net::HTTP)
    parse_check_response get_http(http_klass, 'https://internet.yandex.com')
  end

  def check_tor_ip(http_klass = Net::HTTP)
    parse_check_response get_http(http_klass, 'https://213.180.204.248')  # "internet.yandex.com"
  end

  def my_ip
    disable_socks

    body = get_http(Net::HTTP, 'http://internet.yandex.com')

    if body =~ /My IPv4\: (\d+\.\d+\.\d+\.\d+)/
      @ip = $1
    else
      @ip = nil
    end

  end

  def parse_check_response(body)
    if body =~ /My IPv4: (\d+\.\d+\.\d+\.\d+)/
      ip = $1
    else
      raise 'Bogus response, no IP'
    end

    is_tor = !(@ip == ip)

    [is_tor, ip]
  end

  def test_resolve
    enable_socks

    assert_equal("87.106.131.203", Socksify::resolve("spaceboyz.net"))

    assert_raise SOCKSError::HostUnreachable do
      Socksify::resolve("nonexistent.spaceboyz.net")
    end
  end

  def test_resolve_reverse
    enable_socks

    assert_equal("spaceboyz.net", Socksify::resolve("87.106.131.203"))

    assert_raise SOCKSError::HostUnreachable do
      Socksify::resolve("0.0.0.0")
    end
  end

  def test_proxy
    enable_socks 

    default_server = TCPSocket.socks_server
    default_port = TCPSocket.socks_port

    Socksify.proxy('localhost.example.com', 60001) {
      assert_equal TCPSocket.socks_server, 'localhost.example.com'
      assert_equal TCPSocket.socks_port, 60001
    }

    assert_equal TCPSocket.socks_server, default_server
    assert_equal TCPSocket.socks_port, default_port
  end

  def test_proxy_failback
    enable_socks 

    default_server = TCPSocket.socks_server
    default_port = TCPSocket.socks_port

    assert_raise StandardError do
      Socksify.proxy('localhost.example.com', 60001) {
        raise StandardError.new('error')
      }
    end

    assert_equal TCPSocket.socks_server, default_server
    assert_equal TCPSocket.socks_port, default_port
  end
end



