package com.github.eddykaya;

import org.jboss.logging.Logger;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import javax.mail.Message;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class CustomTermsAndConditions implements RequiredActionProvider {
    //logger for custom use
    private final Logger logger = Logger.getLogger(CustomTermsAndConditions.class);
    private final KeycloakSession keycloakSession;
    private final ExecutorService emailExecutor;
    public CustomTermsAndConditions(KeycloakSession session){
        this.keycloakSession = session;
        this.emailExecutor = Executors.newFixedThreadPool(5);
    }

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }
    //custom mail sender implementation
/*    private void sendEmail(String toAddress, String name_of_user, long remainingDays, long remainingHours, long remainingMinutes) throws Exception {
        Properties properties = new Properties();
        properties.setProperty("mail.smtp.host", "smtp.gmail.com");
        properties.setProperty("mail.smtp.port", "587"); //port 587 for gmail
        properties.setProperty("mail.smtp.auth", "true");
        properties.setProperty("mail.smtp.starttls.enable", "true");
        //authenticate with your mail, lower security on your mail to avoid failure
        Session session = Session.getInstance(properties, new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication("unicommerceaditya@gmail.com", "zxyuwvkchiukftiv");
            }
        });
        // get your message ready to send
        Message message = new MimeMessage(session);
        message.setFrom(new InternetAddress("unicommerceaditya@gmail.com")); // Replace with your email address
        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toAddress));
        message.setSubject("Uniware-Password-Expiry");
        String htmlContent = "<html>" +
                "<body>" +
                "<p>Hi " + name_of_user + ",</p>" +
                "<p>Your Uniware password is going to expire in:</p>" +
                "<p>Days: " + remainingDays + "</p>" +
                "<p>Hours: " + remainingHours + "</p>" +
                "<p>Minutes: " + remainingMinutes + "</p>" +
                "<p>You can update your password now or when it expires.</p>" +
                "<p>Thanks and Regards,</p>" +
                "<p>Team Uniware</p>" +
                "</body>" +
                "</html>";
        message.setContent(htmlContent, "text/html");

        Transport.send(message);
    }*/
    @Override
    public void evaluateTriggers(RequiredActionContext context) {


        //this method gets run whenever a user logs in successfully.
        this.logger.tracef("evaluateTriggers(%s)", context.getUser() != null ? context.getUser().getUsername() : null);
        PasswordCredentialProvider passwordProvider = (PasswordCredentialProvider)context.getSession()
                .getProvider(CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);

        CredentialModel password = passwordProvider.getPassword(context.getRealm(), context.getUser());
        //if it is not the first time user is setting up his password then.
        if (password != null) {
            //update logs
            this.logger.tracef("Found password credentials; Created: %d ms", password.getCreatedDate());
            //if the user has never created a password then,
            if (password.getCreatedDate() == null) {
                context.getUser().addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                this.logger.debug("User is required to update password");
            } else {
                // time the user has created the password. So the policy works like this...
                // instead of storing expiration of password in 90 days what we do here is
                // check if the last created password or updated password was 83 days ago. If yes
                // then send a mail to user asking him to update his password with the number of days it will expire in.
                long timeElapsed = Time.toMillis((long)Time.currentTime())  - password.getCreatedDate();
                this.logger.tracef("time elapsed (%l)",timeElapsed);
                if(timeElapsed > 1000L * 60 * 60 * 24 * 90){
                    context.getUser().addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                    this.logger.debug("User is required to update password");
                }

                else if (timeElapsed > 1000L * 60 * 60 * 24 * 83) {

                    // Given remaining milliseconds
                    long time_left_to_expire_millis = 1000L * 60 * 60 * 24 * 90 - timeElapsed;

                    // Calculate remaining days
                    long remainingDays = time_left_to_expire_millis / (1000L * 60 * 60 * 24);

                    // Calculate remaining hours
                    long remainingHours = (time_left_to_expire_millis % (1000L * 60 * 60 * 24)) / (1000L * 60 * 60);

                    // Calculate remaining minutes
                    long remainingMinutes = (time_left_to_expire_millis % (1000L * 60 * 60)) / (1000L * 60);

                    // Display the results
                    System.out.println("Remaining time: " + remainingDays + " days, " + remainingHours + " hours, " + remainingMinutes + " minutes");


                    String expiration_time = "Remaining time: " + remainingDays + " days, " + remainingHours + " hours, " + remainingMinutes + " minutes";
                    String name_of_user = context.getUser().getFirstName();

                    this.logger.debugf("Found password expiration days");

                    String htmlContent = "<html>" +
                            "<body>" +
                            "<p>Hi " + name_of_user + ",</p>" +
                            "<p>Your Uniware password is going to expire in:</p>" +
                            "<p>Days: " + remainingDays + "</p>" +
                            "<p>Hours: " + remainingHours + "</p>" +
                            "<p>Minutes: " + remainingMinutes + "</p>" +
                            "<p>You can update your password now or when it expires.</p>" +
                            "<p>Thanks and Regards,</p>" +
                            "<p>Team Uniware</p>" +
                            "</body>" +
                            "</html>";
                    //using the existing settings from realm of the user trying to login
                    EmailTemplateProvider emailProvider = keycloakSession.getProvider(EmailTemplateProvider.class);
                    emailProvider.setRealm(context.getRealm());
                    emailProvider.setUser(context.getUser());
                    EmailSenderProvider emailSender = (EmailSenderProvider)this.keycloakSession.getProvider(EmailSenderProvider.class);
                    emailExecutor.submit(() -> {
                                try {
                                    logger.info("Trying to send email to: " + context.getUser().getEmail() + " at " + Time.currentTime());
                                    emailSender.send(context.getRealm().getSmtpConfig(), context.getUser(), "Uniware-password-expiry", "", htmlContent);
                                } catch (EmailException e) {
                                    logger.info("Unable to send email");
                                }
                    });

                    // we use a thread to send email to reduce the time the user has to wait on login screen in order for him to have a better experience.
/*                    emailExecutor.submit(() -> {
                        try {
                            sendEmail(context.getUser().getEmail(), name_of_user, remainingDays, remainingHours, remainingMinutes);
                            logger.tracef("Email notification sent successfully");
                        } catch (Exception e) {
                            logger.tracef("Email not sent");
                            throw new RuntimeException(e);
                        }
                    });*/
                }
            }
        }

    }

    @Override
    public void processAction(RequiredActionContext context) {
        this.logger.tracef("processAction(%s)", context.getUser() != null ? context.getUser().getUsername() : null);
    }
    @Override
    public void close() {
        emailExecutor.shutdown();
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        this.logger.tracef("requiredActionChallenge(%s)", context.getUser() != null ? context.getUser().getUsername() : null);}

}