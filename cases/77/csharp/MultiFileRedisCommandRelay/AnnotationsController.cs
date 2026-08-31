using Microsoft.AspNetCore.Mvc;

namespace MultiFileRedisCommandRelay
{
    [ApiController]
    [Route("api/annotations")]
    public class AnnotationsController : ControllerBase
    {
        private readonly AnnotationService _service;

        public AnnotationsController(AnnotationService service)
        {
            _service = service;
        }

        // Lets a signed-in user attach a short text note to a document they are viewing.
        [HttpPost("{documentId}")]
        public IActionResult AddAnnotation(string documentId, [FromForm] string noteText)
        {
            if (string.IsNullOrEmpty(documentId))
            {
                return BadRequest("documentId is required");
            }

            _service.SaveAnnotation(documentId, noteText);
            return Ok();
        }
    }
}
