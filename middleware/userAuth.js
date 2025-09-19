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

import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
  // get token from cookie
  const { token } = req.cookies;

  if (!token) {
    return res
      .status(401)
      .json({ success: false, message: "Not Authorized. Login Again" });
  }

  try {
    // verify and decode the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded?.id) {
      return res.status(401).json({ success: false, message: "Invalid Token" });
    }

    // ✅ Attach userId without overwriting req.body
    req.user = { id: decoded.id };

    next();
  } catch (error) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid or Expired Token" });
  }
};

export default userAuth;
