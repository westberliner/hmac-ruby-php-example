require_relative "OpenSSLHmacLayer"

hmac = HmacLayer.new(
  'qh3Wh0KLUqjLrLpiAaxlUvcgQyPSnuSxVQRASPNQQvw',
  '5201a261b60a759384ef59ec47fe98dff5a4d3457b21ea2d15b1e5c1355037a3'
)

puts "\nencrypt/decrypt with hmac-sha256, aes-256-cbc \n\n\n"

puts "try: enc/dec php"
enc = `php -e hmac.php \"enc/dec php\"`
puts "encoded: #{enc}"
rmsg = `php -e dechmac.php \"#{enc}\"`
puts "decoded: #{rmsg} \n\n\n"

puts "try: enc/dec php/ruby"
enc = `php -e hmac.php \"enc/dec php/ruby\"`
puts "encoded: #{enc}"
rmsg = hmac.decrypt enc
puts "decoded: #{rmsg} \n\n\n"

puts "try: enc/dec ruby"
enc = hmac.encrypt "enc/dec ruby"
puts "encoded: #{enc}"
rmsg = hmac.decrypt enc
puts "decoded: #{rmsg} \n\n\n"

puts "try: enc/dec ruby/php"
enc = hmac.encrypt "enc/dec ruby/php"
puts "encoded: #{enc}"
rmsg = `php -e dechmac.php \"#{enc}\"`
puts "decoded: #{rmsg} \n\n\n"