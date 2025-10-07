import os

class DeleteFileMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if hasattr(request, 'delete_after_response'):
            file_path = request.delete_after_response
            if os.path.exists(file_path):
                os.remove(file_path)
        return response
