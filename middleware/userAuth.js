import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
  // get token from cookie
  const { token } = req.cookies;

  if (!token) {
    return res.json({ success: false, message: "Not Autherized Login Again" });
  }

  try {
    //I will verify and decode the token
    const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

    // if (tokenDecode.id) {
    //   req.body.userId = tokenDecode.id;
    //   //req.body = { userId: tokenDecode.id };
    // }
    if (tokenDecode.id) {
      req.body = req.body || {};
      req.body.userId = tokenDecode.id;
    } else {
      return res.json({
        success: false,
        message: "Not Autherized Login Again",
      });
    }

    next();
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

export default userAuth;
