class Account < ActiveRecord::Base
  include OtpHandler

  def phone?
    !self.phone.blank?
  end
    
  def activate!
    update_attribute(:activated, true)
  end

  def send_otp_instructions_message(token, message)
    type = phone? ? "send_otp_sms" : "send_otp_email"
    EmailWorker.perform_async(type, self.id, 'opt_message' => message)
  end

  def after_otp_confirmed(params, type)
    if type.to_s.eql? 'forget_password' 
      update_attributes(params)
    elsif type.to_s.eql? 'signup'
      activate!
    end
  end

  def otp_within
    if self.otp_type.eql? 'forget_password' 
      1.hours
    elsif self.otp_type.eql? 'signup'
      24.hours
    else
      1.hours  
    end
  end

  private

  def send_signup_otp
    self.send_otp_instructions(:signup)
  end
end