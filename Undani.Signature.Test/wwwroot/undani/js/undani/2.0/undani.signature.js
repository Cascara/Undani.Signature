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
            "S505": "The rfc number is wrong.",
            "S506": "The curp number is wrong.",
            "S507": "The name is wrong.",
            "S508": "The certificate has expired.",
            "S509": "The signer is not correct.",
            "S510": "The digital signature is invalid.",
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
            return n + ": " + settings.error[n.substring(0, 4)];
        };

        return s;
    }

    $.fn.uSignature = function (settings) {
        var signature = this;
        var token = "";
        var signSuccess = {};
        settings = Settings(settings);

        signature = $.extend(this,
            {
                Sign: function (procedureInstanceRefId, elementInstanceRefId, templates) {
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
                            SignStart(procedureInstanceRefId, elementInstanceRefId, templates);
                        } else {
                            $.ajax({
                                cache: false,
                                url: "/Account/GetToken",
                                dataType: "json",
                                timeout: 1280000
                            })
                                .done(function (result) {
                                    token = result.token;
                                    SignStart(procedureInstanceRefId, elementInstanceRefId, templates);
                                })
                                .fail(function (jqXHR, textStatus, errorThrown) {
                                    signature.trigger("error", settings.loginFail);
                                });
                            }
                        

                    }
                    else
                        signature.trigger("error", settings.getError("S002"));
                }

            });

        function SignStart(procedureInstanceRefId, elementInstanceRefId, templates) {
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
                .done(function (result) {
                    if (result.Error === "") {
                        if (result.Value.length > 0) {
                            for (var i = 0; i < result.Value.length; i++) {
                                signSuccess[result.Value[i].key] = false;
                            }

                            for (var j = 0; j < result.Value.length; j++) {
                                switch (result.Value[j].type) {

                                    case 1:
                                        SignTextEnd(publicKey, privateKey, password, procedureInstanceRefId, elementInstanceRefId, result.Value[j].content, result.Value[j].key, result.Value[j].template);
                                        break;
                                    case 2:
                                        SignPDFEnd(publicKey, privateKey, password, procedureInstanceRefId, elementInstanceRefId, result.Value[j].content, result.Value[j].key, result.Value[j].template);
                                        break;
                                }
                            }
                        }
                        else {
                            signature.trigger("error", settings.getError("S003"));
                        }
                    }
                    else {
                        signature.trigger("error", settings.getError(result.Error));
                    }
                })
                .fail(function (jqXHR, textStatus, errorThrown) {
                    signature.trigger("error", settings.loginFail);
                });
        }

        function SignTextEnd(publicKey, privateKey, password, procedureInstanceRefId, elementInstanceRefId, content, key, template) {            
            Signature.Crypto.SignAsync(privateKey, password, content, "sha256")
                .done(function (result) {
                    if (result.error) {
                        signature.trigger("error", settings.getError("S001"));
                        return false;
                    }
                    
                    var formData = new FormData();
                    formData.append("procedureInstanceRefId", procedureInstanceRefId);
                    formData.append("elementInstanceRefId", elementInstanceRefId);
                    formData.append("key", key);
                    formData.append("template", template);
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
                        .done(function (result) {
                            if (result.Error === "") {
                                if (result.Value === true) {
                                    SignSuccess(key);
                                } else {
                                    signature.trigger("error", settings.getError("S004"));
                                } 
                            }
                            else {
                                signature.trigger("error", settings.getError(result.Error));
                            }
                                                       
                        })
                        .fail(function (jqXHR, textStatus, errorThrown) {
                            signature.trigger("error", errorThrown);
                        });
                })
                .fail(function (result) {
                    signature.trigger("error", settings.getError("S001"));
                });
        }

        function SignPDFEnd(publicKey, privateKey, password, procedureInstanceRefId, elementInstanceRefId, content, key, template) {
            Signature.Crypto.SignAsync(privateKey, password, content, "sha256")
                .done(function (result) {
                    if (result.error) {
                        signature.trigger("error", settings.getError("S001"));
                        return false;
                    }

                    var formData = new FormData();
                    formData.append("procedureInstanceRefId", procedureInstanceRefId);
                    formData.append("elementInstanceRefId", elementInstanceRefId);
                    formData.append("key", key);
                    formData.append("template", template);
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
                        .done(function (result) {
                            if (result.Error === "") {
                                if (result.Value === true) {
                                    SignSuccess(key);
                                } else {
                                    signature.trigger("error", settings.getError("S004"));
                                }
                            }
                            else {
                                signature.trigger("error", settings.getError(result.Error));
                            }
                            
                        })
                        .fail(function (jqXHR, textStatus, errorThrown) {
                            signature.trigger("error", errorThrown);
                        });
                })
                .fail(function (result) {
                    signature.trigger("error", settings.getError("S001"));
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