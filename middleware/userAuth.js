// import jwt from "jsonwebtoken";

// const userAuth = async (req, res, next) => {
//   // get token from cookie
//   const { token } = req.cookies;

//   if (!token) {
//     return res.json({ success: false, message: "Not Autherized Login Again" });
//   }

//   try {
//     //I will verify and decode the token
//     const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

//     if (tokenDecode.id) {
//       req.body.userId = tokenDecode.id;
//       //req.body = { userId: tokenDecode.id };
//     } else {
//       return res.json({
//         success: false,
//         message: "Not Autherized Login Again",
//       });
//     }

//     next();
//   } catch (error) {
//     return res.json({ success: false, message: error.message });
//   }
// };

// export default userAuth;

// Proction
import jwt from "jsonwebtoken";

async function userAuth(req, res, next) {
  const { token } = req.cookies;
  if (!token)
    return res.json({
      success: false,
      message: "Not Authorized! Login Again.",
    });
  try {
    const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);
    if (tokenDecode.id) {
      req.body = { ...req.body, userId: tokenDecode.id }; // merge safely
    } else
      return res.json({
        success: false,
        message: "Not Authorized! Login Again.....",
      });
    next();
  } catch (err) {
    res.json({
      success: false,
      message: err.message,
    });
  }
}

export default userAuth;
