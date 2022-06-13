package handler

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/eErsultan/test-task/dto"
	"github.com/eErsultan/test-task/model"
	"github.com/eErsultan/test-task/mongodb"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

var userCollection *mongo.Collection = mongodb.GetCollection(mongodb.DB, "users")
var refreshTokenCollection *mongo.Collection = mongodb.GetCollection(mongodb.DB, "refresh-token")

var jwtKey = []byte("jwt_super_secret_key")

func Token(w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("userId")
	if len(userId) == 0 && !IsValidUUID(userId) {
		http.Error(w, "invalid userId", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var user model.User
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(userId)
	if err := userCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tokenDto, err := generateJWT()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokenDto)
	return
}

func RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var tokenDto = dto.TokenDto{}
	if err := json.NewDecoder(r.Body).Decode(&tokenDto); err != nil {
		return
	}

	jwt.TimeFunc = func() time.Time {
		return time.Unix(0,0)
	}
	tokenId, err := verifyToken(tokenDto.AccessToken)
	jwt.TimeFunc = time.Now
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var refreshToken model.RefreshToken
	defer cancel()

	if err = refreshTokenCollection.FindOne(ctx, bson.M{"tokenid": tokenId}).Decode(&refreshToken); err != nil {
		http.Error(w, "refresh token not found", http.StatusInternalServerError)
		return
	}

	if refreshToken.Used {
		http.Error(w, "This refresh token has been used", http.StatusForbidden)
		return
	}

	if !checkHash(tokenDto.RefreshToken, refreshToken.Id) {
		http.Error(w, "This refresh token does not exist", http.StatusForbidden)
		return
	}

	update := bson.M{"used": true}
	if _, err := refreshTokenCollection.UpdateOne(ctx, bson.M{"tokenid": tokenId}, bson.M{"$set": update}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newTokenDto, err := generateJWT()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(newTokenDto)
	return
}

func generateJWT() (*dto.TokenDto, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tokenId := uuid.New().String()
	claims := &jwt.StandardClaims{
		Id:        tokenId,
		ExpiresAt: time.Now().Add(time.Minute * 5).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return nil, err
	}

	refreshTokenId := uuid.New().String()
	refreshTokenIdHash, err := hash(refreshTokenId)
	if err != nil {
		return nil, err
	}

	refreshToken := model.RefreshToken{
		Id:      refreshTokenIdHash,
		TokenId: tokenId,
		Used:    false,
	}

	_, err = refreshTokenCollection.InsertOne(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	result := &dto.TokenDto{
		AccessToken:  tokenString,
		RefreshToken: refreshTokenId,
	}

	return result, nil
}

func verifyToken(accessToken string) (string, error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, jwt.ErrSignatureInvalid
		}

		return jwtKey, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		tokenId, _ := claims["jti"].(string)
		return tokenId, nil
	}

	return "", errors.New("invalid token")
}

func hash(text string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(text), 14)
	return string(bytes), err
}

func checkHash(text, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(text))
	return err == nil
}

func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}