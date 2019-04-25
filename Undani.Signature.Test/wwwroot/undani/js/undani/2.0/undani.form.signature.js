(function ($) {

    function Settings(s) {
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

            if (typeof s.token === "undefined" || s.token === "")
                alert("The token is not set");

            if (typeof s.environmentId === "undefined" || s.environmentId === "")
                alert("The environment is not set");

            if (typeof s.instanceId === "undefined" || s.instanceId === "")
                alert("The form instance is not set");

            if (typeof s.publicKey === "undefined")
                s["publicKey"] = settings.publicKey;

            if (typeof s.privateKey === "undefined")
                s["privateKey"] = settings.privateKey;

            if (typeof s.password === "undefined")
                s["password"] = settings.password;
        }

        return s;
    }

    $.fn.uFormSignature = function (settings) {
        var signature = this;
        settings = Settings(settings);

        signature = $.extend(this,
            {
                Sign: function () {
                    var isRequired = true;

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

                        formData.append("token", settings.token);
                        formData.append("environmentId", settings.environmentId);
                        formData.append("formInstanceId", settings.instanceId);
                        formData.append("publicKey", publicKey);

                        signature.trigger("starting");

                        $.ajax({
                            url: settings.host + "/Execution/Sign/FormInstance/Start",
                            data: formData,
                            processData: false,
                            contentType: false,
                            enctype: 'multipart/form-data',
                            type: 'POST',
                            timeout: 1280000
                        })
                            .done(function (result) {
                                if (result.error === '')
                                    SealWithPrivateKey(settings.token, publicKey, privateKey, password, result);
                                else
                                    signature.trigger("error", result.error);
                            })
                            .fail(function (jqXHR, textStatus, errorThrown) {
                                signature.trigger("error", errorThrown);
                            });

                    }
                    else
                        signature.trigger("error", "Ingrese la información requerida para la firma.");
                }
            });

        function SealWithPrivateKey(token, publicKey, privateKey, password, pkr) {
            Signature.Crypto.SignAsync(privateKey, password, pkr.contentAsBase64, "sha256")
                .done(function (result) {
                    if (result.error) {
                        signature.trigger("error", result.error);
                        return;
                    }
                    
                    var formData = new FormData();
                    formData.append("token", token);
                    formData.append("number", pkr.number);
                    formData.append("publicKey", publicKey);
                    formData.append("sealWithPrivateKey", Signature.Crypto.ArrayToBase64(result.signatureAsArray));

                    $.ajax({
                        url: settings.host + "/Execution/Sign/FormInstance/End",
                        data: formData,
                        processData: false,
                        contentType: false,
                        enctype: 'multipart/form-data',
                        type: 'POST',
                        timeout: 1280000
                    })
                        .done(function (result) {
                            if (result === '') {
                                signature.trigger("done");
                            } else {
                                signature.trigger("error", result);
                            }
                            
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