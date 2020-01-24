(function ($) {

    function Settings(s) {
        var error = {
            "S001": "El usuario no es válido, verifique sus datos de e.Firma y vuelva a intentarlo.",
            "S002": "No hay suficiente información para continuar con la firma electrónica.",
            "S003": "No hay elementos para firmar.",
            "S004": "No fue posible firmar el elemento.",
            "S501": "Clave pública no seleccionada.",
            "S502": "La firma digital está vacía.",
            "S503": "El acceso no es válido.",
            "S504": "El certificado es incorrecto.",
            "S505": "El RFC es incorrecto.",
            "S506": "La CURP es incorrecta.",
            "S507": "El nombre es incorrecto.",
            "S508": "El certificado ha caducado.",
            "S509": "El firmante no es correcto.",
            "S510": "La firma digital no es válida.",
            "S511": "La cadena de certificados no cumple con la política.",
            "S512": "No fue posible conectarse con el repositorio de seguridad.",
            "S513": "Ocurrió un problema al intentar validar la revocación del certificado.",
            "S514": "La respuesta del servicio de revocación no tuvo éxito.",
            "S515": "Numero de certificado no encontrado.",
            "S516": "El certificado se encuentra revocado.",
            "S901": "No fue posible agregar la página de trazabilidad en el cuadro.",
            "S902": "No fue posible conectar con el repositorio.",
            "S903": "Se produjo un error al intentar consumir recursos de formulario.",
            "S904": "Se produjo un error al intentar consumir recursos de identidad.",
            "S905": "Se produjo un error al intentar consumir recursos de plantilla.",
            "S906": "Se produjo un error al intentar consumir recursos de seguimiento."
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