import appError from "./appError.js";

export const handleAsync = (fn) => {
    return (req, res, next) => {
      fn(req,res,next).catch((err) => next(new appError(err.message,400)));
    };
  };