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
            publicKey: "publicKey",
            privateKey: "privateKey",
            password: "password"
        };

        if (typeof s === "undefined")
            alert("The host is not set");
        else {
            if (typeof s.host === "undefined" || s.host === "") 
                alert("The host is not set");

            if (typeof s.publicKey === "undefined")
                s["publicKey"] = settings.publicKey;

            if (typeof s.privateKey === "undefined")
                s["privateKey"] = settings.privateKey;

            if (typeof s.password === "undefined")
                s["password"] = settings.password;

            if (typeof s.loginFail === "undefined")
                s["loginFail"] = settings.loginFail;

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

    $.fn.uSignature = function (settings) {
        var signature = this;
        var token = "";
        var signSuccess = {};
        var lastErrorNumber = "";
        settings = Settings(settings);

        signature = $.extend(this,
            {
                Sign: function (procedureInstanceRefId, elementInstanceRefId, templates, represented) {
                    lastErrorNumber = "";
                    var isRequired = true;

                    if (typeof procedureInstanceRefId === "undefined" || procedureInstanceRefId === "")
                        isRequired = false;

                    if (typeof elementInstanceRefId === "undefined" || elementInstanceRefId === "")
                        isRequired = false;

                    if (typeof $("#" + settings.publicKey)[0].files[0] === "undefined" && isRequired === true)
                        isRequired = false;

                    if (typeof $("#" + settings.privateKey)[0].files[0] === "undefined" && isRequired === true)
                        isRequired = false;

                    if ($("#" + settings.password).val() === "" && isRequired === true)
                        isRequired = false;

                    if (isRequired) {

                        if (token !== "") {
                            SignStart(procedureInstanceRefId, elementInstanceRefId, templates, represented);
                        } else {
                            $.ajax({
                                cache: false,
                                url: "/Account/GetToken",
                                dataType: "json",
                                timeout: 1280000
                            })
                                .done(function (result) {
                                    token = result.token;
                                    SignStart(procedureInstanceRefId, elementInstanceRefId, templates, represented);
                                })
                                .fail(function (jqXHR, textStatus, errorThrown) {
                                    signature.trigger("error", errorThrown);
                                });
                        }
                    }
                    else
                        RaiseError("S002");
                }
            });

        function RaiseError(errorNumber) {
            if (errorNumber !== lastErrorNumber) {            
                var errorThrown = settings.getError(errorNumber);
                signature.trigger("error", errorThrown);
                lastErrorNumber = errorNumber;
            }
        }

        function SignStart(procedureInstanceRefId, elementInstanceRefId, templates, represented) {
            var formData = new FormData();
            var publicKey = $("#" + settings.publicKey)[0].files[0];
            var privateKey = $("#" + settings.privateKey)[0].files[0];
            var password = $("#" + settings.password).val();

            formData.append("procedureInstanceRefId", procedureInstanceRefId);
            formData.append("elementInstanceRefId", elementInstanceRefId);
            formData.append("templates", templates);
            formData.append("publicKey", publicKey);

            signature.trigger("starting");

            $.ajax({
                url: settings.host + "/Sign/Start",
                data: formData,
                processData: false,
                contentType: false,
                enctype: "multipart/form-data",
                type: "POST",
                headers: { Authorization: token },
                timeout: 1280000
            })
                .done(function (resultSignature) {
                    if (resultSignature.error === "") {
                        if (resultSignature.value.length > 0) {
                            for (var i = 0; i < resultSignature.value.length; i++) {
                                signSuccess[resultSignature.value[i].key] = false;
                            }

                            for (var j = 0; j < resultSignature.value.length; j++) {
                                switch (resultSignature.value[j].type) {

                                    case 1:
                                        SignTextEnd(publicKey, privateKey, password, procedureInstanceRefId, elementInstanceRefId, resultSignature.value[j].content, resultSignature.value[j].key, resultSignature.value[j].template, represented);
                                        break;
                                    case 2:
                                        SignPDFEnd(publicKey, privateKey, password, procedureInstanceRefId, elementInstanceRefId, resultSignature.value[j].content, resultSignature.value[j].key, resultSignature.value[j].template, represented);
                                        break;
                                }
                            }
                        }
                        else {
                            RaiseError("S003");
                        }
                    }
                    else {
                        RaiseError(resultSignature.error);
                    }
                })
                .fail(function (jqXHR, textStatus, errorThrown) {
                    signature.trigger("error", errorThrown);
                });
        }

        function SignTextEnd(publicKey, privateKey, password, procedureInstanceRefId, elementInstanceRefId, content, key, template, represented) {            
            Signature.Crypto.SignAsync(privateKey, password, content, "sha256")
                .done(function (result) {
                    if (result.error) {
                        RaiseError("S001");
                        return false;
                    }
                    
                    var formData = new FormData();
                    formData.append("procedureInstanceRefId", procedureInstanceRefId);
                    formData.append("elementInstanceRefId", elementInstanceRefId);
                    formData.append("key", key);
                    formData.append("template", template);
                    formData.append("represented", represented);
                    formData.append("publicKey", publicKey);
                    formData.append("digitalSignature", Signature.Crypto.ArrayToBase64(result.signatureAsArray));

                    $.ajax({
                        url: settings.host + "/Sign/Text/End",
                        data: formData,
                        processData: false,
                        contentType: false,
                        enctype: 'multipart/form-data',
                        type: 'POST',
                        headers: { Authorization: token },
                        timeout: 1280000
                    })
                        .done(function (resultSignature) {
                            if (resultSignature.error === "") {
                                if (resultSignature.value === true) {
                                    SignSuccess(key);
                                } else {
                                    RaiseError("S004");
                                } 
                            }
                            else {
                                RaiseError(resultSignature.error);
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

        function SignPDFEnd(publicKey, privateKey, password, procedureInstanceRefId, elementInstanceRefId, content, key, template, represented) {
            Signature.Crypto.SignAsync(privateKey, password, content, "sha256")
                .done(function (result) {
                    if (result.error) {
                        RaiseError("S001");
                        return false;
                    }

                    var formData = new FormData();
                    formData.append("procedureInstanceRefId", procedureInstanceRefId);
                    formData.append("elementInstanceRefId", elementInstanceRefId);
                    formData.append("key", key);
                    formData.append("template", template);
                    formData.append("represented", represented);
                    formData.append("publicKey", publicKey);
                    formData.append("privateKey", privateKey);
                    formData.append("pk", password);
                    formData.append("digitalSignature", Signature.Crypto.ArrayToBase64(result.signatureAsArray));

                    $.ajax({
                        url: settings.host + "/Sign/PDF/End",
                        data: formData,
                        processData: false,
                        contentType: false,
                        enctype: 'multipart/form-data',
                        type: 'POST',
                        headers: { Authorization: token },
                        timeout: 1280000
                    })
                        .done(function (resultSignature) {
                            if (resultSignature.error === "") {
                                if (resultSignature.value === true) {
                                    SignSuccess(key);
                                } else {
                                    RaiseError("S004");
                                }
                            }
                            else {
                                RaiseError(resultSignature.error);
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

        function SignSuccess(currentKey) {
            signSuccess[currentKey] = true;

            var done = true;
            for (var key in signSuccess) {
                if (signSuccess[key] === false)
                    done = false;
            }

            if (done)
                signature.trigger("done");
        }

        return signature;
    };
})(jQuery);