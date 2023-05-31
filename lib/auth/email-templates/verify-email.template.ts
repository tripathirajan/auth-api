export const verifyEmailTemplate = (fullName: string, verificationLink: string) => {
  const text = `
    Hi ${fullName},
    To verify your email, click on this link:
    ${verificationLink}

    If you did not request any password resets, then ignore this email.

    Regards
    Admin
    `;
  const html = `<p>Hi ${fullName}</p>
                    <p>To verify your email, click on this link:</p>
                    <a href='${verificationLink}'>${verificationLink}</a>
                    <br/>
                    <p>If you did not create an account, then ignore this email.</p>
                    <br/>
                    <br/>
                    <p>Regards</p>
                    <p>Admin</p>
                `;
  return { text, html };
};
