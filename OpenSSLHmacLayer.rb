class HmacLayer
  require 'digest'
  require 'openssl'
  require 'cgi'
  require 'base64'

  HMACMETHOD = "sha256"
  CIPHERMETHOD = "AES-256-CBC"
  MACSIZE = 64
  IVSIZE = 16

  def initialize(shared_secret, client_secret)

    @shared_secret = shared_secret
    @client_secret = client_secret
    @hmac_key = Digest::SHA256.hexdigest (@client_secret + @shared_secret);
    @encryption_key = @hmac_key
    @init_vector = OpenSSL::Random.pseudo_bytes(IVSIZE)

  end

  def encrypt msg

    enc = encrypt_msg msg
    enc = @init_vector + enc
    hmacmsg = generate_hmac(enc)

    return CGI.escape(Base64.encode64(hmacmsg))

  end

  def decrypt msg

    msg = Base64.decode64(CGI.unescape(msg))
  
    hmac = msg[0, MACSIZE]
    msg = msg[MACSIZE, msg.length]

    compare_hmac = generate_hmac(msg, false);

    if hmac != compare_hmac
      return false
    end

    iv = msg[0, IVSIZE]
    msg = msg[IVSIZE, msg.length]

    return decrypt_msg iv, msg

  end

  private

  def generate_hmac msg, append = true

    hmac_msg = OpenSSL::HMAC.hexdigest(HMACMETHOD, @hmac_key, msg)

    if append
      return hmac_msg + msg
    end

    return hmac_msg

  end

  def encrypt_msg msg

    cipher = OpenSSL::Cipher::new(CIPHERMETHOD)
    cipher.encrypt
    cipher.key = @encryption_key
    cipher.iv = @init_vector
    enc = cipher.update msg
    enc << cipher.final

    return enc

  end

  def decrypt_msg iv, msg
    begin
      b64 = Base64.urlsafe_decode64 msg
    rescue
      # nothin to do here
    else 
      msg = b64
    end

    
    cipher = OpenSSL::Cipher.new(CIPHERMETHOD)
    cipher.decrypt
    # cipher.padding = 0
    cipher.key = @encryption_key
    cipher.iv = iv

    dec = cipher.update msg
    dec << cipher.final

    return dec

  end

end
