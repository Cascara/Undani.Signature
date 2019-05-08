(function ($) {

    function Settings(s) {
        var settings = {
            publicKey: "publicKey",
            privateKey: "privateKey",
            password: "password",
            loginFail: "El usuario no es valido. Revise sus datos de e.Firma y vuelva a intentarlo."
        };

        if (typeof s === "undefined")
            alert("The host is not set");
        else {
            if (typeof s.host === "undefined" || s.host === "") 
                alert("The host is not set");

            if (typeof s.environmentId === "undefined" || s.environmentId === "")
                alert("The environment is not set");

            if (typeof s.publicKey === "undefined")
                s["publicKey"] = settings.publicKey;

            if (typeof s.privateKey === "undefined")
                s["privateKey"] = settings.privateKey;

            if (typeof s.password === "undefined")
                s["password"] = settings.password;

            if (typeof s.loginFail === "undefined")
                s["loginFail"] = settings.loginFail;
        }

        return s;
    }

    $.fn.uFormSignature = function (settings) {
        var signature = this;
        var token = "";
        settings = Settings(settings);

        signature = $.extend(this,
            {
                SignFormInstance: function (formInstanceId) {
                    var isRequired = true;

                    if (typeof formInstanceId === "undefined" || formInstanceId === "")
                        isRequired = false;

                    if (typeof $("#" + settings.publicKey)[0].files[0] === "undefined" && isRequired === true)
                        isRequired = false;

                    if (typeof $("#" + settings.privateKey)[0].files[0] === "undefined" && isRequired === true)
                        isRequired = false;

                    if ($("#" + settings.password).val() === "" && isRequired === true)
                        isRequired = false;

                    if (isRequired) {

                        if (token !== "") {
                            SignFormInstanceStart(formInstanceId, token);
                        } else {
                            $.ajax({
                                cache: false,
                                url: "/Accoun/GetToken",
                                dataType: "json",
                                timeout: 1280000
                            })
                                .done(function (result) {
                                    token = result.token;
                                    SignFormInstanceStart(formInstanceId);
                                })
                                .fail(function (jqXHR, textStatus, errorThrown) {
                                    signature.trigger("error", settings.loginFail);
                                });
                            }
                        

                    }
                    else
                        signature.trigger("error", settings.loginFail);
                },
                SignBlob: function (systemNames) {
                    if (typeof systemNames === "undefined" || systemNames === "")
                        isRequired = false;

                    if (typeof $("#" + settings.publicKey)[0].files[0] === "undefined" && isRequired === true)
                        isRequired = false;

                    if (typeof $("#" + settings.privateKey)[0].files[0] === "undefined" && isRequired === true)
                        isRequired = false;

                    if ($("#" + settings.password).val() === "" && isRequired === true)
                        isRequired = false;

                    if (isRequired) {

                        if (token !== "") {
                            SignFormInstanceStart(formInstanceId, token);
                        } else {
                            $.ajax({
                                cache: false,
                                url: "/Accoun/GetToken",
                                dataType: "json",
                                timeout: 1280000
                            })
                                .done(function (result) {
                                    token = result.token;
                                    SignFormInstanceStart(formInstanceId);
                                })
                                .fail(function (jqXHR, textStatus, errorThrown) {
                                    signature.trigger("error", settings.loginFail);
                                });
                        }
                    }
                    else
                        signature.trigger("error", settings.loginFail);
                }

            });

        function SignFormInstanceStart(formInstanceId) {
            var formData = new FormData();
            var publicKey = $("#" + settings.publicKey)[0].files[0];
            var privateKey = $("#" + settings.privateKey)[0].files[0];
            var password = $("#" + settings.password).val();

            formData.append("formInstanceId", formInstanceId);
            formData.append("environmentId", settings.environmentId);
            formData.append("publicKey", publicKey);

            signature.trigger("starting");

            $.ajax({
                url: settings.host + "/Sign/FormInstance/Start",
                data: formData,
                processData: false,
                contentType: false,
                enctype: "multipart/form-data",
                type: "POST",
                headers: { Authorization: token },
                timeout: 1280000
            })
                .done(function (content) {
                    if (result.error === '')
                        SignFormInstanceEnd(publicKey, privateKey, password, content);
                    else
                        signature.trigger("error", result.error);
                })
                .fail(function (jqXHR, textStatus, errorThrown) {
                    signature.trigger("error", settings.loginFail);
                });
        }

        function SignFormInstanceEnd(publicKey, privateKey, password, content, token) {
            Signature.Crypto.SignAsync(privateKey, password, content.contentAsBase64, "sha256")
                .done(function (result) {
                    if (result.error) {
                        signature.trigger("error", result.error);
                        return;
                    }
                    
                    var formData = new FormData();
                    formData.append("formInstanceId", formInstanceId);
                    formData.append("environmentId", settings.environmentId);
                    formData.append("publicKey", publicKey);
                    formData.append("digitalSignature", Signature.Crypto.ArrayToBase64(result.signatureAsArray));

                    $.ajax({
                        url: settings.host + "/Sign/FormInstance/End",
                        data: formData,
                        processData: false,
                        contentType: false,
                        enctype: 'multipart/form-data',
                        type: 'POST',
                        headers: { Authorization: token },
                        timeout: 1280000
                    })
                        .done(function (result) {
                            if (result === true) {
                                signature.trigger("done");
                            } else {
                                signature.trigger("error", result);
                            }
                            
                        })
                        .fail(function (jqXHR, textStatus, errorThrown) {
                            signature.trigger("error", settings.loginFail);
                        });
                })
                .fail(function (result) {
                    signature.trigger("error", result.error);
                });
        }

        function SignBlobStart(systemNames) {
            var formData = new FormData();
            var publicKey = $("#" + settings.publicKey)[0].files[0];
            var privateKey = $("#" + settings.privateKey)[0].files[0];
            var password = $("#" + settings.password).val();

            formData.append("systemNames", systemNames);
            formData.append("environmentId", settings.environmentId);
            formData.append("publicKey", publicKey);

            signature.trigger("starting");

            $.ajax({
                url: settings.host + "/Sign/Blob/Start",
                data: formData,
                processData: false,
                contentType: false,
                enctype: 'multipart/form-data',
                type: 'POST',
                headers: { Authorization: token },
                timeout: 1280000
            })
                .done(function (content) {
                    if (result.error === '')
                        SignBlobEnd(publicKey, privateKey, password, content, systemNames);
                    else
                        signature.trigger("error", result.error);
                })
                .fail(function (jqXHR, textStatus, errorThrown) {
                    signature.trigger("error", errorThrown);
                });

        }

        function SignBlobEnd(publicKey, privateKey, password, content, systemNames) {
            Signature.Crypto.SignAsync(privateKey, password, content.contentAsBase64, "sha256")
                .done(function (result) {
                    if (result.error) {
                        signature.trigger("error", result.error);
                        return;
                    }

                    var formData = new FormData();

                    formData.append("environmentId", settings.environmentId);
                    formData.append("systemNames", systemNames);
                    formData.append("publicKey", publicKey);
                    formData.append("privateKey", privateKey);
                    formData.append("pk", password);
                    formData.append("digitalSignature", Signature.Crypto.ArrayToBase64(result.signatureAsArray));

                    $.ajax({
                        url: settings.host + "/Sign/Document/End",
                        data: formData,
                        processData: false,
                        contentType: false,
                        enctype: 'multipart/form-data',
                        headers: { Authorization: token },
                        type: 'POST'
                    })
                        .done(function (result) {
                            if (result === true)
                                signature.trigger("done");
                            else
                                signature.trigger("error", result);
                        })
                        .fail(function (jqXHR, textStatus, errorThrown) {
                            signature.trigger("error", errorThrown);
                        });
                })
                .fail(function (result) {
                    signature.trigger("error", result.error);
                });
        }

        return signature;
    };
})(jQuery);