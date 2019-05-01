<?php
 
namespace App\Http\Controllers;
 
use JWTAuth;
use Illuminate\Http\Request;
use App\Http\Traits\AuthTrait;


class AuthController extends Controller
{
    use AuthTrait;

    public $loginAfterSignUp = true;
 
    public function register(Request $request)
    {
        $rules = $this->validateSignupRequest($request);
    
        if($rules->fails()){
            $errors = $rules->errors();
            return $errors->toJson(400);
        }

        $user = $this->createNewUser($request);

        if ($this->loginAfterSignUp) {
            return $this->login($request);
        }
 
        return response()->json([
            'success' => true,
            'data' => $user
        ], 200);
    }
 
    public function login(Request $request)
    {
        $input = $request->only('email', 'password');
        return $this->sanitizeUser($input);
    }
 
    public function logout(Request $request)
    {
        $this->validate($request, [
            'token' => 'required'
        ]);
 
        return $this->logUserOff($request);
    }
 
    public function getAuthUser(Request $request)
    {
        $this->validate($request, [
            'token' => 'required'
        ]);
 
        $user = JWTAuth::authenticate($request->token);
 
        return response()->json(['user' => $user]);
    }

}