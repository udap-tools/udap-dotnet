#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Udap.Common.Models;
using Udap.Idp.Admin.Services.DataBase;
using Udap.Server.Mappers;

[Route("api/[controller]")]
[ApiController]
public class AnchorController : ControllerBase
{
    IAnchorService _anchorService;
    ILogger<AnchorController> _logger;

    public AnchorController(IAnchorService anchorService, ILogger<AnchorController> logger)
    {
        _anchorService = anchorService;
        _logger = logger;
    }

    // GET: api/<AnchorController>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<Anchor>>> GetAsync(CancellationToken token)
    {
        var entitities = await _anchorService.Get(token);

        if (!entitities.Any())
        {
            return NotFound();
        }

        var communities = entitities.Select(e => e.ToModel());

        return Ok(communities);
    }

    // GET api/<AnchorController>/5
    [HttpGet("{id}")]
    public async Task<ActionResult<Anchor>> Get(int id, CancellationToken token)
    {
        var entity = await _anchorService.Get(id, token);

        if (entity == null)
        {
            return NotFound();
        }
        var anchor = entity.ToModel();

        return Ok(anchor);
    }

    // POST api/<AnchorController>
    [HttpPost]
    public async Task<ActionResult<Anchor>> Post([FromBody] Anchor value, CancellationToken token)
    {
        try
        {
            var result = await _anchorService.Add(value.ToEntity(), token).ConfigureAwait(false);

            return Created(result.Id.ToString(), result.ToModel());
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Error calling {0}", nameof(Post));

            //
            // TODO: Waiting to see if Hellang ProblemDetails package adds some nice
            // extension helpers for Dotnet 7.0
            // remember dotnet 7.0 now has problem details built in.
            //

            // if (ex.InnerException != null &&
            //     (ex.InnerException.Message.Contains("duplicate")
            //      || ex.InnerException.Message.Contains("UNIQUE")))
            // {
            //     var problemDetails = new ProblemDetails()
            //     {
            //         Status = StatusCodes.Status409Conflict,
            //         Detail = UdapStoreError.UniqueConstraint.ToString(),
            //         Type = "https://httpstatuses.com/409"
            //     };
            //
            //     throw new (problemDetails);
            // }
            // else
            // {
            //     var problemDetails = new ProblemDetails()
            //     {
            //         Status = StatusCodes.Status400BadRequest,
            //         Detail = "Check the logs",
            //         Type = "https://httpstatuses.com/400"
            //     };
            //
            //     throw new Exception(problemDetails);
            // }
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calling {0}", nameof(Get));
            throw;
        }
    }

    // PUT api/<AnchorController>/5
    [HttpPut("{id}")]
    public async Task<ActionResult> Put(int id, [FromBody] Anchor value, CancellationToken token)
    {
        try
        {
            await _anchorService.Update(value.ToEntity(), token).ConfigureAwait(false);

            return NoContent(); // https://www.rfc-editor.org/rfc/rfc9110.html#name-204-no-content
            // Although... https://blog.ploeh.dk/2013/04/30/rest-lesson-learned-avoid-204-responses/
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Error calling {0}", nameof(Put));

            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calling {0}", nameof(Put));
            throw;
        }
    }

    // DELETE api/<AnchorController>/5
    [HttpDelete("{id}")]
    public async Task<ActionResult<bool>> Delete(int id, CancellationToken token)
    {
        var response = await _anchorService.Delete(id, token);

        if (response)
        {
            return Ok();
        }

        return NotFound();
    }
}