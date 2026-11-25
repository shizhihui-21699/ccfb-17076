require 'net/http'
require 'json'

module OAuth
  # 真实网络传输的唯一出口，便于在测试里整体替换成 MockTransport
  class HttpTransport
    Response = Struct.new(:status, :body, :headers, keyword_init: true) do
      def json
        JSON.parse(body)
      rescue JSON::ParserError
        raise OAuth::TransportError, "invalid JSON response (status #{status})"
      end
    end

    class << self
      def get(url, headers: {}, query: nil)
        uri = URI(url)
        uri.query = URI.encode_www_form(query) if query.present?
        request = Net::HTTP::Get.new(uri)
        headers.each { |k, v| request[k] = v }
        dispatch(uri, request)
      end

      def post_form(url, form:, headers: {})
        uri = URI(url)
        request = Net::HTTP::Post.new(uri)
        headers.each { |k, v| request[k] = v }
        request.set_form_data(form)
        dispatch(uri, request)
      end

      private

      def dispatch(uri, request)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.open_timeout = 5
        http.read_timeout = 10
        res = http.request(request)
        Response.new(status: res.code.to_i, body: res.body.to_s,
                     headers: res.each_header.to_h)
      rescue StandardError => e
        raise OAuth::TransportError, "HTTP request to #{uri.host} failed: #{e.class}: #{e.message}"
      end
    end
  end

  class TransportError < StandardError; end
  class ProviderError < StandardError; end
end
