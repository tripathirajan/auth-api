export const resetPasswordTemplate = (fullName: string, resetLink: string) => {
  const text = `
    Hi ${fullName},
    Click on the link below to reset your password:
    ${resetLink}

    If you did not request any password resets, then ignore this email.

    Regards
    Admin
    `;
  const html = `<p>Hi ${fullName}</p>
                    <p>Click on the link below to reset your password:</p>
                    <a href='${resetLink}'>${resetLink}</a>
                    <br/>
                    <p>If you did not request any password resets, then ignore this email.</p>
                    <br/>
                    <br/>
                    <p>Regards</p>
                    <p>Admin</p>
                `;
  return { text, html };
};
