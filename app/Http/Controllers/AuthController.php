<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\Exceptions\HttpResponseException;

use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Validator;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }

    /**
    * Get a JWT via given credentials.
    *
    * @return \Illuminate\Http\JsonResponse
    * Redirect to the Auth0 hosted login page
    *
    * @return mixed
    */
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');
        $verifyEmail = $this->verifyEmail($credentials);
        if (!$verifyEmail) {
            return response()->json([
                'success' => false,
                'code' => 1,
                'message' => 'Wrong validation, bad email structure or empty password',
            ], 422);
        }

        $token = JWTAuth::attempt($credentials);

        if ($token) {

            return response()->json([
                'token' => $token,
                'user' => User::where('email', $credentials['email'])->get()->first()
            ], 200);
        } else {
            return response()->json([
                'success' => false,
                'code' => 2,
                'message' => 'Wrong credentials'], 401);
        }
    }
    /**
     * Verify email and password structure.
     *
     * @param  string $validator
     *
     */
    protected function verifyEmail($validator)
    {
        $validator = Validator::make($validator, [
            'email' => 'required|email',
            'password' => 'required',
        ]);
        
        if ($validator->fails()) {
            return false;
        }else{
            return true;
        }
    }
}