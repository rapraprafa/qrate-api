from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK


class ResponseUtils:
    @staticmethod
    def send_error_response(status_code, message):
        return Response({"status_code": status_code, "message": message}, status=status_code)

    @staticmethod
    def get_error_response(status_code, message):
        body = {"status_code": status_code, "message": message}
        status = status_code
        return (body, status)

    @staticmethod
    def send_error_response_delete_member_by_clinician(status_code, message, error_type):
        return Response(
            {"status_code": status_code, "message": message, "type": error_type},
            status=status_code,
        )

    @staticmethod
    def send_success_response(message):
        return Response({"status_code": HTTP_200_OK, "message": message}, status=HTTP_200_OK)
