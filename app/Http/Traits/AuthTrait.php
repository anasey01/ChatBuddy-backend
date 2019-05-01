<?php

namespace App\Http\Traits;

use JWTAuth;
use Validator;
use App\Models\User;
use Tymon\JWTAuth\Exceptions\JWTException;

trait AuthTrait {

  public function validateSignupRequest($request)
  {
    $rules = Validator::make($request->all(),[
      'first_name' => 'required|string',
      'last_name' => 'required|string',
      'email' => 'required|email|unique:users',
      'password' => 'required|string|min:6|max:10'
  ]);

    return $rules;

  }

  public function createNewUser($request)
  {
    return User::create($request->all());
  }

  public function sanitizeUser($input)
  {
    $jwt_token = null;

      try {
          // attempt to verify the credentials and create a token for the user
          if (!$jwt_token = JWTAuth::attempt($input)) {
              return response()->json([
                  'success' => false,
                  'message' => 'Invalid Email or Password',
              ], 401);
          }
      } catch (JWTException $e) {
          // something went wrong whilst attempting to encode the token
          return response()->json(['error' => 'could_not_create_token'], 500);
      }

      // all good so return the token
      return response()->json([
          'success' => true,
          'data' => compact('jwt_token'),
      ]);
  }

  public function logUserOff($request)
  {
    try {
      JWTAuth::invalidate($request->token);

      return response()->json([
          'success' => true,
          'message' => 'User logged out successfully'
      ]);
  } catch (JWTException $exception) {
      return response()->json([
          'success' => false,
          'message' => 'Sorry, the user cannot be logged out'
      ], 500);
  }
  }
}
