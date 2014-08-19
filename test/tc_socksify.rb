#!/usr/bin/ruby

require 'test/unit'
require 'net/http'
require 'uri'

$:.unshift "#{File::dirname($0)}/../lib/"
require 'socksify'
require 'socksify/http'

# XXX: Monkey patches
module URI
  class Generic
    def empty?
      self.to_s.empty?
    end
  end
end

class SocksifyTest < Test::Unit::TestCase
  def setup
    Socksify::debug = true
  end

  def disable_socks
    TCPSocket.socks_server = nil
    TCPSocket.socks_port = nil
  end
  def enable_socks
    TCPSocket.socks_server = "127.0.0.1"
    TCPSocket.socks_port = 9150
  end

  def http_tor_proxy
    Net::HTTP::SOCKSProxy("127.0.0.1", 9150)
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

    [['Hostname', :check_tor],
     ['IPv4', :check_tor_ip]].each do |f_name, f|
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
    TCPSocket.socks_ignores << 'check.torproject.org'

    tor_socks_ignored, ip_socks_ignored = check_tor
    assert_equal(false, tor_socks_ignored)

    assert(ip_direct == ip_socks_ignored)
  end

  def get_http(http_klass, url)
    uri = URI(url)
    body = nil
    http_klass.start(uri.host, uri.port,
                     :use_ssl => uri.scheme == 'https',
                     :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|
      req = Net::HTTP::Get.new uri
      req['Host'] = "check.torproject.org"
      req['User-Agent'] = "ruby-socksify test"
      body = http.request(req).body
    end
    body
  end

  def check_tor(http_klass = Net::HTTP)
    parse_check_response get_http(http_klass, 'https://check.torproject.org/')
  end

  def check_tor_ip(http_klass = Net::HTTP)
    parse_check_response get_http(http_klass, 'https://38.229.72.22/')  # "check.torproject.org"
  end

  def parse_check_response(body)
    if body.include? 'This browser is configured to use Tor.'
      is_tor = true
    elsif body.include? 'You are not using Tor.'
      is_tor = false
    else
      raise "Bogus response #{body}"
    end

    if body =~ /Your IP address appears to be:\s*<strong>(\d+\.\d+\.\d+\.\d+)<\/strong>/
      ip = $1
    else
      raise 'Bogus response, no IP'
    end
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



