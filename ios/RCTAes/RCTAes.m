//
//  RCTAes.m
//  RCTAes
//
//  Created by tectiv3 on 10/02/17.
//  Copyright (c) 2017 tectiv3. All rights reserved.
//


#import "RCTAes.h"
#import "AesCrypto.h"

@implementation RCTAes

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(encrypt:(NSString *)data key:(NSString *)key iv:(NSString *)iv
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *base64 = [AesCrypto encrypt:data key:key iv:iv];
    if (base64 == nil) {
        reject(@"encrypt_fail", @"Encrypt error", error);
    } else {
        resolve(base64);
    }
}

RCT_EXPORT_METHOD(decrypt:(NSString *)base64 key:(NSString *)key iv:(NSString *)iv
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *data = [AesCrypto decrypt:base64 key:key iv:iv];
    if (data == nil) {
        reject(@"decrypt_fail", @"Decrypt failed", error);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(pbkdf2:(NSString *)password salt:(NSString *)salt
                  cost:(NSInteger)cost length:(NSInteger)length
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *data = [AesCrypto pbkdf2:password salt:salt cost:cost length:length];
    if (data == nil) {
        reject(@"keygen_fail", @"Key generation failed", error);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(hmac256:(NSString *)base64 key:(NSString *)key
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *data = [AesCrypto hmac256:base64 key:key];
    if (data == nil) {
        reject(@"hmac_fail", @"HMAC error", error);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(sha1:(NSString *)text
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *data = [AesCrypto sha1:text];
    if (data == nil) {
        reject(@"sha1_fail", @"Hash error", error);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(sha256:(NSString *)text
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *data = [AesCrypto sha256:text];
    if (data == nil) {
        reject(@"sha256_fail", @"Hash error", error);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(sha512:(NSString *)text
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *data = [AesCrypto sha512:text];
    if (data == nil) {
        reject(@"sha512_fail", @"Hash error", error);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(randomUuid:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *data = [AesCrypto randomUuid];
    if (data == nil) {
        reject(@"uuid_fail", @"Uuid error", error);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(randomKey:(NSInteger)length
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *data = [AesCrypto randomKey:length];
    if (data == nil) {
        reject(@"random_fail", @"Random key error", error);
    } else {
        resolve(data);
    }
}

@end
