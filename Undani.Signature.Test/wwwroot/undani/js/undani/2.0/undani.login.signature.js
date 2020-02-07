(function ($) {

    function Settings(s) {
        var error = {
            "S001": "The user is not valid, check your e.Firma data and try again.",
            "S002": "There is not enough information to continue with the electronic signature.",
            "S003": "There are no elements to sign.",
            "S004": "It was not possible to sign the element.",
            "S501": "Public key no selected.",
            "S502": "The digital signature is empty.",
            "S503": "The access is invalid.",
            "S504": "Certificate is wrong.",
            "S505": "The reference number is wrong.",
            "S506": "The population unique identifier is wrong.",
            "S507": "The name is wrong.",
            "S508": "The certificate has expired.",
            "S509": "The signer is not correct.",
            "S510": "The digital signature is invalid.",
            "S511": "The certificate chain does not comply with the policy.",
            "S512": "Failed to obtain the JWT token.",
            "S513": "There was a problem trying to validate the certificate revocation.",
            "S514": "The response of the revocaion service was not successful.",
            "S515": "Serial number not found.",
            "S516": "The certificate is revoked.",
            "S901": "It was not possible to add the traceability page in box.",
            "S902": "It was not possible to connect with repository.",
            "S903": "There was an error when trying to consume form resources.",
            "S904": "There was an error when trying to consume identity resources.",
            "S905": "There was an error when trying to consume template resources.",
            "S906": "There was an error when trying to consume tracking resources."
        };

        var settings = {
            ownerId: "00000000-0000-0000-0000-000000000000",
            publicKey: "publicKey",
            privateKey: "privateKey",
            password: "password"
        };

        if (typeof s === "undefined")
            alert("The host is not set");
        else {
            if (typeof s.host === "undefined" || s.host === "")
                alert("The host is not set");

            if (typeof s.ownerId === "undefined")
                s["ownerId"] = settings.ownerId;

            if (typeof s.publicKey === "undefined")
                s["publicKey"] = settings.publicKey;

            if (typeof s.privateKey === "undefined")
                s["privateKey"] = settings.privateKey;

            if (typeof s.password === "undefined")
                s["password"] = settings.password;

            if (typeof $.signatureError === "undefined")
                s["error"] = error;
            else
                s["error"] = $.signatureError;
        }

        s["getError"] = function (n) {
            return this.error[n.substring(0, 4)] + " (" + n + ")";
        };

        return s;
    }

    $.fn.uLoginSignature = function (settings) {
        var signature = this;
        var _user = {};
        var lastErrorNumber = "";
        settings = Settings(settings);

        signature = $.extend(this,
            {
                Login: function (content) {
                    var isRequired = true;

                    if (typeof content === "undefined")
                        content = {};

                    if (typeof $("#" + settings.publicKey)[0].files[0] === "undefined")
                        isRequired = false;

                    if (typeof $("#" + settings.privateKey)[0].files[0] === "undefined" && isRequired === true)
                        isRequired = false;

                    if ($("#" + settings.password).val() === "" && isRequired === true)
                        isRequired = false;

                    if (isRequired) {

                        var formData = new FormData();
                        var publicKey = $("#" + settings.publicKey)[0].files[0];
                        var privateKey = $("#" + settings.privateKey)[0].files[0];
                        var password = $("#" + settings.password).val();

                        formData.append("publicKey", publicKey);

                        signature.trigger("starting");

                        $.ajax({
                            url: settings.host + "/Sign/Login/Start",
                            data: formData,
                            processData: false,
                            contentType: false,
                            enctype: 'multipart/form-data',
                            type: 'POST',
                            timeout: 1280000
                        })
                            .done(function (result) {
                                if (result.error === "") {
                                    SealWithPrivateKey(publicKey, privateKey, password, result.value, content);
                                } else {
                                    RaiseError(result.error);
                                }
                            })
                            .fail(function (jqXHR, textStatus, errorThrown) {
                                signature.trigger("error", errorThrown);
                            });

                    }
                    else
                        RaiseError("S002");
                },
                ContentExists: function (content) {
                    var formData = new FormData();
                    formData.append("ownerId", settings.ownerId);
                    formData.append("content", JSON.stringify(content));

                    $.ajax({
                        url: settings.host + "/Sign/User/ContentExists",
                        data: formData,
                        processData: false,
                        contentType: false,
                        enctype: 'multipart/form-data',
                        type: 'POST',
                        timeout: 1280000
                    })
                        .done(function (exists) {
                            signature.trigger("contentexists", exists);
                        })
                        .fail(function (jqXHR, textStatus, errorThrown) {
                            signature.trigger("error", errorThrown);
                        });
                },
                User: function () {
                    return _user;
                }
            });

        function RaiseError(errorNumber) {
            if (errorNumber !== lastErrorNumber) {
                var errorThrown = settings.getError(errorNumber);
                signature.trigger("error", errorThrown);
                lastErrorNumber = errorNumber;
            }
        }

        function SealWithPrivateKey(publicKey, privateKey, password, signNumber, content) {
            Signature.Crypto.SignAsync(privateKey, password, signNumber, "sha256")
                .done(function (result) {
                    if (result.error) {
                        RaiseError("S001");
                        return;
                    }

                    var formData = new FormData();
                    formData.append("ownerId", settings.ownerId);
                    formData.append("publicKey", publicKey);
                    formData.append("digitalSignature", Signature.Crypto.ArrayToBase64(result.signatureAsArray));
                    formData.append("content", JSON.stringify(content));

                    $.ajax({
                        url: settings.host + "/Sign/Login/End",
                        data: formData,
                        processData: false,
                        contentType: false,
                        enctype: 'multipart/form-data',
                        type: 'POST',
                        timeout: 1280000
                    })
                        .done(function (result) {
                            if (result.error === "") {
                                _user = result.value;
                                signature.trigger("done", result.value);
                            }
                            else {
                                RaiseError(result.error);
                            }
                        })
                        .fail(function (jqXHR, textStatus, errorThrown) {
                            signature.trigger("error", errorThrown);
                        });
                })
                .fail(function (result) {
                    RaiseError("S001");
                });
        }

        return signature;
    };
})(jQuery);