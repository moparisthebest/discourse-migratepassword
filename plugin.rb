# name: discourse-migratepassword
# about: enable alternative password hashes
# version: 0.7
# authors: Jens Maier and Michael@discoursehosting.com
 
# uses phpass-ruby https://github.com/uu59/phpass-ruby

# Usage:
# When migrating, store a custom field with the user containing the crypted password

# for vBulletin this should be #{password}:#{salt}      md5(md5(pass) + salt)
# for vBulletin5               #{token}                 bcrypt(md5(pass))
# for Phorum                   #{password}              md5(pass)
# for Wordpress                #{password}              phpass(8).crypt(pass)
# for SMF                      #{username}:#{password}  sha1(user+pass)
# for WBBlite                  #{salt}:#{hash}          sha1(salt+sha1(salt+sha1(pass)))


# for scrypt
#gem 'rake'
#gem 'ffi'
#gem 'ffi-compiler'
#gem 'scrypt', '3.0.1'

require 'digest'

after_initialize do
 
    module ::AlternativePassword
        def confirm_password?(password)
            return true if super
            return false unless (self.custom_fields.has_key?('sha_pass') || self.custom_fields.has_key?('scrypt_sha_pass'))

            if AlternativePassword::check_smf(password, self.custom_fields['import_username'], self.custom_fields['sha_pass']) #|| AlternativePassword::check_smf_scrypt(password, self.custom_fields['import_username'], self.custom_fields['scrypt_sha_pass'])
                self.password = password
                self.custom_fields.delete('sha_pass')
                self.custom_fields.delete('scrypt_sha_pass')
                return save
            end
            false
        end

        def self.check_smf(password, user, hash)
            sha1 = Digest::SHA1.new
            sha1.update user + password
            hash == sha1.hexdigest
        end

        #def self.check_smf_scrypt(password, user, hash)
        #    sha1 = Digest::SHA1.new
        #    sha1.update user + password
        #    begin
        #      SCrypt::Password.new(hash) == sha1.hexdigest
        #    rescue
        #      false
        #    end
        #end
    end
 
    class ::User
        prepend AlternativePassword
    end
 
end

