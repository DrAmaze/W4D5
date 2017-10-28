class User < ApplicationRecord

  validates :email, :session_token, uniqueness: true
  validates :password, length: { minimum: 6, allow_nil: true }
  validates :email, :session_token, :password_digest, presence: true

  after_initialize :ensure_session_token

  attr_readaer :password

  def self.generate_unqiue_session_token
    token = SecureRandom.urlsafe_base64
    while User.exists?(session_token: token)
      token = SecureRandom.urlsafe_base64
    end
    token
  end

  def reset_session_token!
    self.session_token = SecureRandom.urlsafe_base64
    self.save
    self.session_token
  end

  def ensure_session_token
    self.session_token ||= SecureRandom.urlsafe_base64
  end

  def password=(pw)
    @password = pw
    self.password_digest = BCrypt::Password.create(pw)
  end

  def is_password?(pw)
    password = BCrypt::Password.new(self.password_digest)
    password.is_password?(pw)
  end

  def self.find_by_credentials(email, pw)
    user = User.find_by(email: email)
    return nil if user.nil?
    user.is_password?(pw) ? user : nil
  end
end
